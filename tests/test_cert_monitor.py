from __future__ import annotations

import base64
import json
import logging
import os
import ssl
import threading
import warnings
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import paho.mqtt.client as mqtt
import pytest
import yaml
from paho.mqtt.packettypes import PacketTypes
from paho.mqtt.reasoncodes import ReasonCode

import cert_monitor as monitor

BLUEPRINT_PATH = Path(__file__).resolve().parents[1] / 'blueprints' / 'automation' / 'homelab_cert_expiring.yaml'


def _der_tlv(tag: int, body: bytes) -> bytes:
    length = len(body)
    if length < 0x80:
        len_bytes = bytes([length])
    else:
        raw_len = length.to_bytes((length.bit_length() + 7) // 8, 'big')
        len_bytes = bytes([0x80 | len(raw_len)]) + raw_len
    return bytes([tag]) + len_bytes + body


def _der_time(dt: datetime, *, generalized: bool) -> bytes:
    utc_dt = dt.astimezone(UTC)
    if generalized:
        return _der_tlv(0x18, utc_dt.strftime('%Y%m%d%H%M%SZ').encode('ascii'))
    return _der_tlv(0x17, utc_dt.strftime('%y%m%d%H%M%SZ').encode('ascii'))


def _build_test_cert_pem(
    not_after: datetime,
    *,
    generalized: bool = False,
    include_version: bool = True,
) -> str:
    version = _der_tlv(0xA0, _der_tlv(0x02, b'\x02')) if include_version else b''
    serial = _der_tlv(0x02, b'\x01')
    sig_alg = _der_tlv(0x30, _der_tlv(0x06, b'\x2a\x86\x48\xce\x3d\x04\x03\x02'))
    issuer = _der_tlv(0x30, b'')
    not_before = _der_time(datetime(2025, 12, 1, 0, 0, 0, tzinfo=UTC), generalized=generalized)
    validity = _der_tlv(0x30, not_before + _der_time(not_after, generalized=generalized))
    tbs = _der_tlv(0x30, version + serial + sig_alg + issuer + validity)
    cert_der = _der_tlv(0x30, tbs + sig_alg + _der_tlv(0x03, b'\x00'))
    b64 = base64.encodebytes(cert_der).decode('ascii')
    return f'-----BEGIN CERTIFICATE-----\n{b64}-----END CERTIFICATE-----\n'


# ---------------------------------------------------------------------------
# load_env & load_config
# ---------------------------------------------------------------------------


def test_load_env_missing_and_valid(tmp_path: Path) -> None:
    assert monitor.load_env(tmp_path / 'missing.env') == {}

    env_path = tmp_path / 'cert_monitor.env'
    env_path.write_text(
        """
        # comment
        BROKER="mqtt.example.com"
        MQTT_PORT='8884'
        INVALID_LINE
        =NO_KEY
        TOPIC='homeassistant/sensor/custom_certs///'
        """,
        encoding='utf-8',
    )
    parsed = monitor.load_env(env_path)
    assert parsed['BROKER'] == 'mqtt.example.com'
    assert parsed['MQTT_PORT'] == '8884'
    assert 'INVALID_LINE' not in parsed


def test_load_config_defaults_and_overrides(tmp_path: Path) -> None:
    defaults = monitor.Config()
    assert defaults.publish_interval_sec == 60.0
    assert defaults.extra_certs == ()
    assert defaults.alert_threshold_days == 7.0
    assert monitor.load_config(tmp_path / 'missing.env').alert_threshold_days == 7.0

    env_path = tmp_path / 'cert_monitor.env'
    systemd_dir = tmp_path / 'systemd'
    cert_a = tmp_path / 'a.crt'
    cert_b = tmp_path / 'b.crt'
    env_path.write_text(
        f"""
        BROKER=broker.local
        MQTT_PORT=8884
        TOPIC="homeassistant/sensor/custom_certs///"
        CLIENT_ID=custom-monitor
        PUBLISH_INTERVAL_SEC=120
        SYSTEMD_DIR="{systemd_dir}"
        CERTS="alpha:{cert_a}, beta : {cert_b}"
        ALERT_THRESHOLD_DAYS=3.5
        """,
        encoding='utf-8',
    )
    cfg = monitor.load_config(env_path)

    assert cfg.broker == 'broker.local'
    assert cfg.mqtt_port == 8884
    assert cfg.topic_base == 'homeassistant/sensor/custom_certs'
    assert cfg.client_id == 'custom-monitor'
    assert cfg.publish_interval_sec == 120.0
    assert cfg.systemd_dir == systemd_dir
    assert cfg.extra_certs == (('alpha', cert_a), ('beta', cert_b))
    assert cfg.alert_threshold_days == 3.5


@pytest.mark.parametrize(
    'env_content',
    [
        'MQTT_PORT=0',
        'MQTT_PORT=70000',
        'MQTT_PORT=bad',
        'PUBLISH_INTERVAL_SEC=0',
        'PUBLISH_INTERVAL_SEC=bad',
        'ALERT_THRESHOLD_DAYS=0',
        'ALERT_THRESHOLD_DAYS=-1',
        'ALERT_THRESHOLD_DAYS=week',
        'TOPIC=/',
        'BROKER=',
        'CERTS=missing_colon',
        'CERTS=:only_path',
        'CERTS=only_name:',
    ],
)
def test_load_config_validation_errors(tmp_path: Path, env_content: str) -> None:
    env_path = tmp_path / 'bad.env'
    env_path.write_text(env_content, encoding='utf-8')
    with pytest.raises(ValueError, match=r'Invalid|must'):
        monitor.load_config(env_path)


# ---------------------------------------------------------------------------
# discover_profile_certs
# ---------------------------------------------------------------------------


def _add_systemd_profile(systemd_dir: Path, name: str, cert_path: str | None, *, enabled: bool = True) -> None:
    if enabled:
        wants_dir = systemd_dir / 'timers.target.wants'
        wants_dir.mkdir(parents=True, exist_ok=True)
        (wants_dir / f'cert-renewer@{name}.timer').write_text('[Install]\n', encoding='utf-8')
    if cert_path is not None:
        dropin_dir = systemd_dir / f'cert-renewer@{name}.service.d'
        dropin_dir.mkdir(parents=True, exist_ok=True)
        (dropin_dir / 'override.conf').write_text(f'[Service]\nEnvironment=CERT_PATH={cert_path}\n', encoding='utf-8')


def test_discover_profile_certs_reads_enabled_timers_and_merges_extra(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    systemd_dir = tmp_path / 'systemd'
    wants_dir = systemd_dir / 'timers.target.wants'
    wants_dir.mkdir(parents=True)
    (wants_dir / 'unrelated.timer').write_text('', encoding='utf-8')

    _add_systemd_profile(systemd_dir, 'rpi-stats', '/etc/mosquitto/certs/rpi_stats.crt', enabled=True)
    _add_systemd_profile(systemd_dir, 'zigbee2mqtt', '"/home/pi/z2m/client.crt"', enabled=True)
    _add_systemd_profile(systemd_dir, 'disabled-profile', str(tmp_path / 'disabled.crt'), enabled=False)
    _add_systemd_profile(systemd_dir, 'no-override', None, enabled=True)

    override_path = tmp_path / 'override.crt'
    extra_path = tmp_path / 'custom.crt'
    with caplog.at_level(logging.WARNING):
        profiles = monitor.discover_profile_certs(
            systemd_dir,
            extra_certs=(('rpi-stats', override_path), ('custom-svc', extra_path)),
        )

    by_name = {p.name: p for p in profiles}
    assert set(by_name) == {'custom-svc', 'no-override', 'rpi-stats', 'zigbee2mqtt'}
    # Enabled timer without CERT_PATH stays monitored (reported as unreadable) instead of silently disappearing.
    assert by_name['no-override'].cert_path is None
    assert any('cert-renewer@no-override.timer' in rec.getMessage() for rec in caplog.records)
    assert by_name['rpi-stats'].cert_path == override_path
    assert by_name['rpi-stats'].slug == 'rpi_stats'
    assert by_name['rpi-stats'].display_name == 'RPi Stats'
    assert by_name['zigbee2mqtt'].cert_path == monitor.Path('/home/pi/z2m/client.crt')
    assert by_name['zigbee2mqtt'].display_name == 'Zigbee2MQTT'
    assert by_name['custom-svc'].slug == 'custom_svc'
    assert by_name['custom-svc'].display_name == 'Custom Svc'


# ---------------------------------------------------------------------------
# CertExpiryTracker & LastSeenTracker
# ---------------------------------------------------------------------------


def test_cert_expiry_tracker_mtime_invalidation_and_caching(tmp_path: Path) -> None:
    cert_file = tmp_path / 'client.crt'
    cert_file.write_text(_build_test_cert_pem(datetime(2026, 12, 24, 12, 0, 0, tzinfo=UTC)), encoding='utf-8')
    os.utime(cert_file, (1_700_000_000, 1_700_000_000))

    tracker = monitor.CertExpiryTracker(cert_file, refresh_interval_sec=3600.0)
    now_utc = datetime(2026, 11, 24, 12, 0, 0, tzinfo=UTC)

    assert tracker.sample(now_monotonic=100.0, now_utc=now_utc) == 30.0

    # Writing a new cert with a new mtime_ns immediately invalidates the cache before 3600s elapses.
    cert_file.write_text(_build_test_cert_pem(datetime(2027, 1, 23, 12, 0, 0, tzinfo=UTC)), encoding='utf-8')
    os.utime(cert_file, (1_700_000_100, 1_700_000_100))
    assert tracker.sample(now_monotonic=160.0, now_utc=now_utc) == 60.0


def test_cert_expiry_tracker_generalized_time_v1_and_expired(tmp_path: Path) -> None:
    cert_file = tmp_path / 'future.crt'
    cert_file.write_text(
        _build_test_cert_pem(datetime(2055, 6, 15, 0, 0, 0, tzinfo=UTC), generalized=True, include_version=False),
        encoding='utf-8',
    )

    tracker = monitor.CertExpiryTracker(cert_file, refresh_interval_sec=60.0)
    assert tracker.sample(now_monotonic=0.0, now_utc=datetime(2055, 6, 5, 0, 0, 0, tzinfo=UTC)) == 10.0
    assert tracker.sample(now_monotonic=10.0, now_utc=datetime(2055, 6, 20, 0, 0, 0, tzinfo=UTC)) == 0.0


def test_cert_expiry_tracker_missing_warns_once_and_handles_corrupt(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    tracker = monitor.CertExpiryTracker(tmp_path / 'missing.crt', refresh_interval_sec=10.0)
    with caplog.at_level(logging.WARNING):
        assert tracker.sample(now_monotonic=0.0) is None
        assert tracker.sample(now_monotonic=20.0) is None

    warnings_logged = [rec for rec in caplog.records if rec.levelno == logging.WARNING]
    assert len(warnings_logged) == 1

    bad_file = tmp_path / 'bad.crt'
    bad_file.write_text('not pem', encoding='utf-8')
    assert monitor.CertExpiryTracker(bad_file).sample(now_monotonic=0.0) is None


def test_cert_expiry_tracker_sample_detail_reports_error_reasons(tmp_path: Path) -> None:
    missing = monitor.CertExpiryTracker(tmp_path / 'missing.crt').sample_detail(now_monotonic=0.0)
    assert missing == monitor.CertSample(days_left=None, expired=False, error='missing')

    bad_file = tmp_path / 'bad.crt'
    bad_file.write_text('not pem', encoding='utf-8')
    corrupt = monitor.CertExpiryTracker(bad_file).sample_detail(now_monotonic=0.0)
    assert corrupt == monitor.CertSample(days_left=None, expired=False, error='parse_error')

    no_path = monitor.CertExpiryTracker(None).sample_detail(now_monotonic=0.0)
    assert no_path == monitor.CertSample(days_left=None, expired=False, error='no_cert_path')


def test_cert_expiry_tracker_sample_detail_expired_uses_raw_not_after(tmp_path: Path) -> None:
    cert_file = tmp_path / 'client.crt'
    cert_file.write_text(_build_test_cert_pem(datetime(2026, 11, 24, 12, 0, 0, tzinfo=UTC)), encoding='utf-8')
    tracker = monitor.CertExpiryTracker(cert_file)

    # ~43 minutes left: rounds to 0.0 days but is NOT expired yet.
    almost = tracker.sample_detail(now_monotonic=0.0, now_utc=datetime(2026, 11, 24, 11, 17, 0, tzinfo=UTC))
    assert almost == monitor.CertSample(days_left=0.0, expired=False, error=None)

    expired = tracker.sample_detail(now_monotonic=1.0, now_utc=datetime(2026, 11, 25, 0, 0, 0, tzinfo=UTC))
    assert expired == monitor.CertSample(days_left=0.0, expired=True, error=None)


# ---------------------------------------------------------------------------
# collect_metrics & alert summary
# ---------------------------------------------------------------------------


class FakeTracker:
    def __init__(self, sample: monitor.CertSample) -> None:
        self._sample = sample

    def sample_detail(self) -> monitor.CertSample:
        return self._sample


class FixedLastSeen:
    def sample(self) -> str:
        return '2026-11-24T12:00:00+00:00'


def _monitored(*items: tuple[str, monitor.CertSample]) -> tuple[monitor.MonitoredCert, ...]:
    return tuple(
        monitor.MonitoredCert(
            monitor.CertProfile(name=name, cert_path=Path(f'/certs/{name}.crt')),
            FakeTracker(sample),  # type: ignore[arg-type]
        )
        for name, sample in items
    )


def _collect(*items: tuple[str, monitor.CertSample], threshold: float = 7.0) -> dict[str, object]:
    return monitor.collect_metrics(_monitored(*items), FixedLastSeen(), threshold)  # type: ignore[arg-type]


def test_collect_metrics_all_healthy_keeps_top_level_keys() -> None:
    payload = _collect(
        ('rpi-stats', monitor.CertSample(days_left=29.8)),
        ('zigbee2mqtt', monitor.CertSample(days_left=29.9)),
        ('cert-monitor', monitor.CertSample(days_left=30.0)),
    )

    assert payload['last_seen'] == '2026-11-24T12:00:00+00:00'
    assert payload['rpi_stats_days_left'] == 29.8
    assert payload['zigbee2mqtt_days_left'] == 29.9
    assert payload['cert_monitor_days_left'] == 30.0
    assert payload['alert'] == {
        'expiring_soon': False,
        'threshold_days': 7.0,
        'profiles_count': 3,
        'expiring_count': 0,
        'min_days_left': 29.8,
        'expiring': [],
        'unreadable': [],
        'all_certs': {
            'rpi_stats': {'name': 'RPi Stats', 'days_left': 29.8},
            'zigbee2mqtt': {'name': 'Zigbee2MQTT', 'days_left': 29.9},
            'cert_monitor': {'name': 'Cert Monitor', 'days_left': 30.0},
        },
    }
    json.dumps(payload)  # must be JSON-serializable


def test_collect_metrics_expiring_sorted_and_threshold_is_strict() -> None:
    payload = _collect(
        ('rpi-stats', monitor.CertSample(days_left=5.2)),
        ('zigbee2mqtt', monitor.CertSample(days_left=0.0, expired=True)),
        ('cert-monitor', monitor.CertSample(days_left=7.0)),
    )
    alert = payload['alert']
    assert isinstance(alert, dict)
    assert alert['expiring_soon'] is True
    assert alert['expiring_count'] == 2
    assert alert['min_days_left'] == 0.0
    assert alert['expiring'] == [
        {'slug': 'zigbee2mqtt', 'name': 'Zigbee2MQTT', 'days_left': 0.0, 'expired': True},
        {'slug': 'rpi_stats', 'name': 'RPi Stats', 'days_left': 5.2, 'expired': False},
    ]


def test_collect_metrics_unreadable_reasons() -> None:
    payload = _collect(
        ('zeta', monitor.CertSample(days_left=None, error='parse_error')),
        ('alpha', monitor.CertSample(days_left=None, error='missing')),
        ('beta', monitor.CertSample(days_left=None, error='no_cert_path')),
        ('rpi-stats', monitor.CertSample(days_left=20.0)),
    )
    assert 'alpha_days_left' not in payload
    alert = payload['alert']
    assert isinstance(alert, dict)
    assert alert['expiring_soon'] is True
    assert alert['expiring'] == []
    assert alert['expiring_count'] == 3
    assert alert['min_days_left'] == 20.0
    assert alert['unreadable'] == [
        {'slug': 'alpha', 'name': 'Alpha', 'reason': 'missing'},
        {'slug': 'beta', 'name': 'Beta', 'reason': 'no_cert_path'},
        {'slug': 'zeta', 'name': 'Zeta', 'reason': 'parse_error'},
    ]
    assert alert['all_certs']['alpha'] == {'name': 'Alpha', 'days_left': None}  # type: ignore[index]


def test_collect_metrics_no_profiles_is_a_problem() -> None:
    payload = _collect()
    assert payload['alert'] == {
        'expiring_soon': True,
        'threshold_days': 7.0,
        'profiles_count': 0,
        'expiring_count': 0,
        'min_days_left': None,
        'expiring': [],
        'unreadable': [],
        'all_certs': {},
    }


def test_collect_metrics_profile_named_min_does_not_collide_with_alert() -> None:
    payload = _collect(('min', monitor.CertSample(days_left=3.0)), ('max', monitor.CertSample(days_left=25.0)))
    assert payload['min_days_left'] == 3.0
    alert = payload['alert']
    assert isinstance(alert, dict)
    assert alert['min_days_left'] == 3.0
    assert alert['expiring_count'] == 1


def test_last_seen_tracker_throttles_updates(monkeypatch: pytest.MonkeyPatch) -> None:
    clock: dict[str, object] = {
        'mono': 100.0,
        'utc': datetime(2026, 11, 24, 12, 0, 0, tzinfo=UTC),
    }

    class FakeDatetime:
        @staticmethod
        def now(tz: object = None) -> datetime:
            assert tz is UTC
            utc_now = clock['utc']
            assert isinstance(utc_now, datetime)
            return utc_now

    monkeypatch.setattr(monitor.time, 'monotonic', lambda: clock['mono'])
    monkeypatch.setattr(monitor, 'datetime', FakeDatetime)

    tracker = monitor.LastSeenTracker(refresh_interval_sec=60.0)
    assert tracker.sample() == '2026-11-24T12:00:00+00:00'

    clock['mono'] = 130.0
    clock['utc'] = datetime(2026, 11, 24, 12, 0, 30, tzinfo=UTC)
    assert tracker.sample() == '2026-11-24T12:00:00+00:00'

    clock['mono'] = 160.0
    clock['utc'] = datetime(2026, 11, 24, 12, 1, 0, tzinfo=UTC)
    assert tracker.sample() == '2026-11-24T12:01:00+00:00'


# ---------------------------------------------------------------------------
# MQTT Discovery, Client & Main Loop
# ---------------------------------------------------------------------------


class RecordingClient:
    def __init__(self, *, connected: bool = True) -> None:
        self.published: list[tuple[str, str | None, int, bool]] = []
        self.connected = connected
        self.calls: list[str] = []
        self.connect_async_args: tuple[str, int, int] | None = None

    def publish(self, topic: str, payload: str | None = None, qos: int = 0, retain: bool = False) -> SimpleNamespace:
        self.published.append((topic, payload, qos, retain))
        return SimpleNamespace(rc=mqtt.MQTT_ERR_SUCCESS)

    def is_connected(self) -> bool:
        return self.connected

    def connect_async(self, host: str, port: int, keepalive: int) -> None:
        self.connect_async_args = (host, port, keepalive)
        self.calls.append('connect_async')

    def loop_start(self) -> None:
        self.calls.append('loop_start')

    def disconnect(self) -> None:
        self.calls.append('disconnect')

    def loop_stop(self) -> None:
        self.calls.append('loop_stop')


@pytest.mark.parametrize(
    ('topic_base', 'component', 'object_id', 'expected'),
    [
        (
            'homeassistant/sensor/homelab_certs',
            'sensor',
            'rpi_stats_days_left',
            'homeassistant/sensor/homelab_certs/rpi_stats_days_left/config',
        ),
        (
            'homeassistant/sensor/homelab_certs',
            'binary_sensor',
            'status',
            'homeassistant/binary_sensor/homelab_certs/status/config',
        ),
        (
            'sensor/homelab_certs',
            'binary_sensor',
            'status',
            'binary_sensor/homelab_certs/status/config',
        ),
        (
            'custom/certs',
            'binary_sensor',
            'status',
            'custom/certs/binary_sensor/status/config',
        ),
    ],
)
def test_discovery_topic_maps_components(
    topic_base: str,
    component: str,
    object_id: str,
    expected: str,
) -> None:
    assert monitor._discovery_topic(topic_base, component, object_id) == expected


def test_publish_discovery_emits_homelab_certificates_device(tmp_path: Path) -> None:
    cfg = monitor.Config(topic_base='homeassistant/sensor/homelab_certs', publish_interval_sec=60.0)
    profiles = (
        monitor.CertProfile(name='cert-monitor', cert_path=tmp_path / 'cm.crt'),
        monitor.CertProfile(name='rpi-stats', cert_path=tmp_path / 'rpi.crt'),
        monitor.CertProfile(name='zigbee2mqtt', cert_path=tmp_path / 'z2m.crt'),
    )
    client = RecordingClient()

    monitor.publish_discovery(client, cfg, profiles)  # type: ignore[arg-type]

    assert len(client.published) == 6
    by_topic = {topic: (json.loads(payload or '{}'), retain) for topic, payload, _qos, retain in client.published}

    expected_topics = {
        f'{cfg.topic_base}/last_seen/config',
        f'{cfg.topic_base}/cert_monitor_days_left/config',
        f'{cfg.topic_base}/rpi_stats_days_left/config',
        f'{cfg.topic_base}/zigbee2mqtt_days_left/config',
        'homeassistant/binary_sensor/homelab_certs/status/config',
        'homeassistant/binary_sensor/homelab_certs/expiring_soon/config',
    }
    assert set(by_topic) == expected_topics
    assert all(retain for _cfg, retain in by_topic.values())

    status_cfg, _ = by_topic['homeassistant/binary_sensor/homelab_certs/status/config']
    assert status_cfg['unique_id'] == 'homelab_certs_status'
    assert status_cfg['device_class'] == 'connectivity'
    assert status_cfg['entity_category'] == 'diagnostic'
    assert status_cfg['state_topic'] == f'{cfg.topic_base}/availability'
    assert 'availability_topic' not in status_cfg
    assert 'expire_after' not in status_cfg
    assert 'value_template' not in status_cfg
    assert 'json_attributes_topic' not in status_cfg

    expiring_cfg, _ = by_topic['homeassistant/binary_sensor/homelab_certs/expiring_soon/config']
    assert expiring_cfg['unique_id'] == 'homelab_certs_expiring_soon'
    assert expiring_cfg['name'] == 'Expiring Soon'
    assert expiring_cfg['device_class'] == 'problem'
    assert 'entity_category' not in expiring_cfg
    assert expiring_cfg['state_topic'] == f'{cfg.topic_base}/state'
    assert (expiring_cfg['payload_on'], expiring_cfg['payload_off']) == ('ON', 'OFF')
    assert 'value_json.alert.expiring_soon' in expiring_cfg['value_template']
    assert 'this.state' not in expiring_cfg['value_template']
    assert expiring_cfg['json_attributes_topic'] == f'{cfg.topic_base}/state'
    assert 'value_json.alert | tojson' in expiring_cfg['json_attributes_template']
    assert expiring_cfg['availability_topic'] == f'{cfg.topic_base}/availability'
    assert expiring_cfg['expire_after'] == 360
    assert expiring_cfg['device']['identifiers'] == ['homelab_certificates']

    last_seen_cfg, _ = by_topic[f'{cfg.topic_base}/last_seen/config']
    assert last_seen_cfg['unique_id'] == 'homelab_certs_last_seen'
    assert last_seen_cfg['device_class'] == 'timestamp'
    assert last_seen_cfg['entity_category'] == 'diagnostic'
    assert 'availability_topic' not in last_seen_cfg
    assert 'expire_after' not in last_seen_cfg

    z2m_cfg, _ = by_topic[f'{cfg.topic_base}/zigbee2mqtt_days_left/config']
    assert z2m_cfg['unique_id'] == 'homelab_certs_zigbee2mqtt_days_left'
    assert z2m_cfg['name'] == 'Zigbee2MQTT Cert Days Left'
    assert z2m_cfg['unit_of_measurement'] == 'd'
    assert z2m_cfg['device_class'] == 'duration'
    assert z2m_cfg['state_class'] == 'measurement'
    assert 'entity_category' not in z2m_cfg
    assert z2m_cfg['availability_topic'] == f'{cfg.topic_base}/availability'
    assert z2m_cfg['expire_after'] == 360
    assert z2m_cfg['device']['identifiers'] == ['homelab_certificates']


def test_create_mqtt_client_on_connect_and_on_disconnect(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    tls_calls: list[dict[str, object]] = []
    will_calls: list[tuple[str, object, int, bool]] = []

    def fake_tls_set(self: mqtt.Client, **kwargs: object) -> None:
        tls_calls.append(kwargs)
        self._ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    def fake_will_set(
        _self: mqtt.Client,
        topic: str,
        payload: object = None,
        qos: int = 0,
        retain: bool = False,
    ) -> None:
        will_calls.append((topic, payload, qos, retain))

    monkeypatch.setattr(mqtt.Client, 'tls_set', fake_tls_set)
    monkeypatch.setattr(mqtt.Client, 'will_set', fake_will_set)

    cfg = monitor.Config(
        broker='mqtt.example.com',
        mqtt_cafile='/ca.crt',
        mqtt_cert='/cert_monitor.crt',
        mqtt_key='/cert_monitor.key',
    )
    context = monitor.MonitorContext(config=cfg, profiles=())

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter('always', DeprecationWarning)
        client = monitor.create_mqtt_client(context)

    assert not [w for w in caught if issubclass(w.category, DeprecationWarning)]
    assert client.callback_api_version == mqtt.CallbackAPIVersion.VERSION2
    assert client.user_data_get() == context
    assert will_calls == [(f'{cfg.topic_base}/availability', 'offline', 1, True)]
    assert tls_calls[0]['certfile'] == '/cert_monitor.crt'

    rec_ok = RecordingClient()
    monitor.on_connect(rec_ok, context, None, ReasonCode(PacketTypes.CONNACK, identifier=0))  # type: ignore[arg-type]
    assert len(rec_ok.published) == 4  # last_seen + status + expiring_soon + availability

    rec_fail = RecordingClient()
    monitor.on_connect(rec_fail, context, None, ReasonCode(PacketTypes.CONNACK, identifier=135))  # type: ignore[arg-type]
    assert rec_fail.published == []

    with caplog.at_level(logging.INFO):
        monitor.on_disconnect(None, None, None, ReasonCode(PacketTypes.DISCONNECT, identifier=0))  # type: ignore[arg-type]
        monitor.on_disconnect(None, None, None, ReasonCode(PacketTypes.DISCONNECT, identifier=142))  # type: ignore[arg-type]

    assert any(rec.levelno == logging.INFO for rec in caplog.records)
    assert any(rec.levelno == logging.WARNING for rec in caplog.records)


def test_main_publishes_discovered_certs_and_shuts_down(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    systemd_dir = tmp_path / 'systemd'
    cert_pem = _build_test_cert_pem(datetime(2030, 1, 1, 0, 0, 0, tzinfo=UTC))
    rpi_cert = tmp_path / 'rpi_stats.crt'
    z2m_cert = tmp_path / 'z2m.crt'
    cm_cert = tmp_path / 'cert_monitor.crt'
    for path in (rpi_cert, z2m_cert, cm_cert):
        path.write_text(cert_pem, encoding='utf-8')

    _add_systemd_profile(systemd_dir, 'rpi-stats', str(rpi_cert))
    _add_systemd_profile(systemd_dir, 'zigbee2mqtt', str(z2m_cert))
    _add_systemd_profile(systemd_dir, 'cert-monitor', str(cm_cert))

    fake_client = RecordingClient(connected=True)
    monkeypatch.setattr(monitor, 'create_mqtt_client', lambda _ctx: fake_client)

    stop_event = threading.Event()
    original_wait = stop_event.wait

    def stop_immediately(_timeout: float | None = None) -> bool:
        stop_event.set()
        return original_wait(0)

    monkeypatch.setattr(stop_event, 'wait', stop_immediately)

    cfg = monitor.Config(broker='mqtt.example.com', systemd_dir=systemd_dir, publish_interval_sec=60.0)
    monitor.main(config=cfg, stop_event=stop_event)

    assert fake_client.calls == ['connect_async', 'loop_start', 'disconnect', 'loop_stop']
    state_msgs = [msg for msg in fake_client.published if msg[0] == f'{cfg.topic_base}/state']
    assert len(state_msgs) == 1
    payload = json.loads(state_msgs[0][1] or '{}')
    assert datetime.fromisoformat(payload['last_seen']).tzinfo is not None
    assert payload['rpi_stats_days_left'] > 0
    assert payload['zigbee2mqtt_days_left'] > 0
    assert payload['cert_monitor_days_left'] > 0
    assert payload['alert']['expiring_soon'] is False
    assert payload['alert']['profiles_count'] == 3
    assert payload['alert']['threshold_days'] == 7.0

    avail_msgs = [msg for msg in fake_client.published if msg[0] == f'{cfg.topic_base}/availability']
    assert avail_msgs == [(f'{cfg.topic_base}/availability', 'offline', 1, True)]


def test_main_recovers_from_transient_error_when_disconnected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_client = RecordingClient(connected=False)
    monkeypatch.setattr(monitor, 'create_mqtt_client', lambda _ctx: fake_client)

    calls = 0

    def flaky_collect(
        _monitored: tuple[monitor.MonitoredCert, ...],
        _last_seen: monitor.LastSeenTracker,
        _threshold: float,
    ) -> dict[str, object]:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError('transient error')
        return {'last_seen': '2026-11-24T12:00:00+00:00'}

    monkeypatch.setattr(monitor, 'collect_metrics', flaky_collect)

    stop_event = threading.Event()
    waits = 0

    def stop_on_second(_timeout: float | None = None) -> bool:
        nonlocal waits
        waits += 1
        if waits >= 2:
            stop_event.set()
        return stop_event.is_set()

    monkeypatch.setattr(stop_event, 'wait', stop_on_second)

    cfg = monitor.Config(systemd_dir=tmp_path / 'empty')
    monitor.main(config=cfg, stop_event=stop_event)

    assert calls == 2
    assert fake_client.published == []
    assert fake_client.calls == ['connect_async', 'loop_start', 'disconnect', 'loop_stop']


# ---------------------------------------------------------------------------
# Home Assistant Blueprint
# ---------------------------------------------------------------------------


class InputRef:
    def __init__(self, name: str) -> None:
        self.name = name


class BlueprintLoader(yaml.SafeLoader):
    """SafeLoader subclass that understands the Home Assistant `!input` tag (global SafeLoader stays untouched)."""


def _construct_input(loader: yaml.SafeLoader, node: yaml.Node) -> InputRef:
    assert isinstance(node, yaml.ScalarNode)
    return InputRef(loader.construct_scalar(node))


BlueprintLoader.add_constructor('!input', _construct_input)


def _load_blueprint() -> dict[str, object]:
    loader = BlueprintLoader(BLUEPRINT_PATH.read_text(encoding='utf-8'))
    try:
        data = loader.get_single_data()
    finally:
        loader.dispose()
    assert isinstance(data, dict)
    return data


def _walk(node: object) -> list[object]:
    items = [node]
    if isinstance(node, dict):
        for value in node.values():
            items.extend(_walk(value))
    elif isinstance(node, list):
        for value in node:
            items.extend(_walk(value))
    return items


def test_blueprint_metadata_and_inputs() -> None:
    data = _load_blueprint()
    blueprint = data['blueprint']
    assert isinstance(blueprint, dict)
    assert blueprint['domain'] == 'automation'
    assert str(blueprint['source_url']).endswith('/blueprints/automation/homelab_cert_expiring.yaml')
    assert blueprint['homeassistant']['min_version'] == '2024.10.0'
    assert data['mode'] == 'queued'

    declared = set(blueprint['input'])
    assert declared == {
        'cert_problem_sensor',
        'for_duration',
        'reminder_time',
        'enable_persistent_notification',
        'notification_title',
        'enable_stale_alert',
        'stale_duration',
        'notify_actions',
    }

    used = {item.name for item in _walk(data) if isinstance(item, InputRef)}
    assert used == declared, 'every !input must reference a declared input and every input must be used'


def test_blueprint_template_inputs_are_declared_as_variables() -> None:
    data = _load_blueprint()
    variables = data['variables']
    assert isinstance(variables, dict)
    declared_inputs = set(data['blueprint']['input'])  # type: ignore[index]

    templates = [item for item in _walk({k: v for k, v in data.items() if k != 'blueprint'}) if isinstance(item, str)]
    templates = [t for t in templates if '{{' in t or '{%' in t]
    assert templates

    for name in declared_inputs:
        if any(name in template for template in templates):
            ref = variables.get(name)
            assert isinstance(ref, InputRef), f'input {name!r} is used in a template but missing in variables'
            assert ref.name == name


def test_blueprint_triggers_and_manual_run_branch() -> None:
    data = _load_blueprint()
    assert 'trigger' not in data
    assert 'action' not in data
    triggers = data['triggers']
    assert isinstance(triggers, list)
    by_id = {t['id']: t for t in triggers}
    assert set(by_id) == {'expiring', 'escalated', 'reminder', 'recovered', 'stale', 'monitor_back'}
    assert all('platform' not in t for t in triggers)

    assert by_id['expiring']['to'] == 'on'
    assert set(by_id['expiring']['not_from']) == {'unavailable', 'unknown'}
    assert by_id['escalated']['attribute'] == 'expiring_count'
    assert set(by_id['stale']['to']) == {'unavailable', 'unknown'}

    text = BLUEPRINT_PATH.read_text(encoding='utf-8')
    # Manual "Run actions" passes trigger={'platform': None}, so the branch must key off a missing trigger.id.
    assert 'trigger is not defined' not in text
    assert 'trigger.id is not defined' in text
    assert '\r' not in text
