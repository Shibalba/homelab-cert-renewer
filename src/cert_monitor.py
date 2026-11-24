"""MQTT v5 mTLS certificate expiry monitor daemon for Home Assistant Discovery."""

from __future__ import annotations

import base64
import contextlib
import json
import logging
import signal
import ssl
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

import paho.mqtt.client as mqtt

if TYPE_CHECKING:
    from types import FrameType

    from paho.mqtt.client import ConnectFlags, DisconnectFlags
    from paho.mqtt.properties import Properties
    from paho.mqtt.reasoncodes import ReasonCode

logger = logging.getLogger('cert_monitor')

ENV_PATH = Path('/etc/cert_monitor.env')
DEFAULT_SYSTEMD_DIR = Path('/etc/systemd/system')
TIMER_PREFIX = 'cert-renewer@'
TIMER_SUFFIX = '.timer'
CERT_PATH_PREFIX = 'Environment=CERT_PATH='

MIN_QUOTED_LEN = 2
MAX_MQTT_PORT = 65535
KEY_VALUE_PARTS = 2
MIN_EXPIRE_AFTER_SEC = 360
EXPIRE_MULTIPLIER = 6
LAST_SEEN_INTERVAL_SEC = 60.0
CERT_REFRESH_INTERVAL_SEC = 3600.0
SECONDS_PER_DAY = 86400.0
MQTT_KEEPALIVE_SEC = 60
DEFAULT_ALERT_THRESHOLD_DAYS = 7.0

CERT_ERROR_MISSING = 'missing'
CERT_ERROR_PARSE = 'parse_error'
CERT_ERROR_NO_CERT_PATH = 'no_cert_path'

DER_SEQUENCE_TAG = 0x30
DER_EXPLICIT_VERSION_TAG = 0xA0
DER_UTC_TIME_TAG = 0x17
DER_GENERALIZED_TIME_TAG = 0x18
DER_LONG_FORM_BIT = 0x80
DER_LONG_FORM_MASK = 0x7F
UTC_TIME_PIVOT_YEAR = 50
UTC_TIME_CENTURY_1900 = 1900
UTC_TIME_CENTURY_2000 = 2000
PEM_CERT_BEGIN = '-----BEGIN CERTIFICATE-----'
PEM_CERT_END = '-----END CERTIFICATE-----'

PROFILE_DISPLAY_NAMES: dict[str, str] = {
    'rpi-stats': 'RPi Stats',
    'zigbee2mqtt': 'Zigbee2MQTT',
    'cert-monitor': 'Cert Monitor',
    'mosquitto': 'Mosquitto',
}

DEVICE_JSON: dict[str, object] = {
    'identifiers': ['homelab_certificates'],
    'name': 'Homelab Certificates',
    'model': 'Smallstep Auto-Renewer',
    'manufacturer': 'Homelab',
}


@dataclass(frozen=True)
class CertProfile:
    """Certificate profile discovered from systemd or explicit configuration."""

    name: str
    cert_path: Path | None

    @property
    def slug(self) -> str:
        """Return an identifier-safe underscore slug for Home Assistant keys."""
        return self.name.replace('-', '_')

    @property
    def display_name(self) -> str:
        """Return a human-readable profile name."""
        if self.name in PROFILE_DISPLAY_NAMES:
            return PROFILE_DISPLAY_NAMES[self.name]
        return self.name.replace('-', ' ').replace('_', ' ').title()


@dataclass(frozen=True)
class Config:
    """Daemon runtime configuration."""

    broker: str = 'mqtt.your.domain'
    mqtt_port: int = 8883
    mqtt_cafile: str = '/etc/step/root_ca.crt'
    mqtt_cert: str = '/etc/mosquitto/certs/cert_monitor.crt'
    mqtt_key: str = '/etc/mosquitto/certs/cert_monitor.key'
    topic_base: str = 'homeassistant/sensor/homelab_certs'
    client_id: str = 'homelab-cert-monitor'
    publish_interval_sec: float = 60.0
    systemd_dir: Path = DEFAULT_SYSTEMD_DIR
    extra_certs: tuple[tuple[str, Path], ...] = ()
    alert_threshold_days: float = DEFAULT_ALERT_THRESHOLD_DAYS


@dataclass(frozen=True)
class SensorSpec:
    """Home Assistant MQTT Discovery sensor specification."""

    object_id: str
    json_key: str
    name: str
    unique_id: str
    unit_of_measurement: str | None = None
    state_class: str | None = None
    device_class: str | None = None
    icon: str | None = None
    entity_category: str | None = 'diagnostic'
    use_availability: bool = True
    use_expire_after: bool = True


@dataclass(frozen=True)
class BinarySensorSpec:
    """Home Assistant MQTT Discovery binary_sensor specification."""

    object_id: str
    name: str
    unique_id: str
    device_class: str | None = None
    icon: str | None = None
    entity_category: str | None = 'diagnostic'
    state_topic_suffix: str = 'availability'
    payload_on: str = 'online'
    payload_off: str = 'offline'
    use_availability: bool = False
    use_expire_after: bool = False
    value_template: str | None = None
    json_attributes_template: str | None = None


@dataclass(frozen=True)
class MonitorContext:
    """Runtime bundle stored in MQTT client userdata."""

    config: Config
    profiles: tuple[CertProfile, ...]


STATUS_BINARY_SENSOR = BinarySensorSpec(
    object_id='status',
    name='Status',
    unique_id='homelab_certs_status',
    device_class='connectivity',
    icon='mdi:lan-connect',
)

EXPIRING_SOON_BINARY_SENSOR = BinarySensorSpec(
    object_id='expiring_soon',
    name='Expiring Soon',
    unique_id='homelab_certs_expiring_soon',
    device_class='problem',
    icon='mdi:alert-decagram-outline',
    entity_category=None,
    state_topic_suffix='state',
    payload_on='ON',
    payload_off='OFF',
    use_availability=True,
    use_expire_after=True,
    value_template=(
        "{% if value_json.alert is defined %}{{ 'ON' if value_json.alert.expiring_soon else 'OFF' }}{% endif %}"
    ),
    json_attributes_template="{{ value_json.alert | tojson if value_json.alert is defined else '{}' }}",
)

LAST_SEEN_SENSOR = SensorSpec(
    object_id='last_seen',
    json_key='last_seen',
    name='Last Seen',
    unique_id='homelab_certs_last_seen',
    device_class='timestamp',
    icon='mdi:clock-check-outline',
    use_availability=False,
    use_expire_after=False,
)


def _strip_quotes(value: str) -> str:
    """Strip matching surrounding single or double quotes from an env value."""
    if len(value) >= MIN_QUOTED_LEN and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def _parse_positive_float(raw: dict[str, str], key: str, default: float) -> float:
    raw_value = raw.get(key, str(default))
    try:
        parsed = float(raw_value)
    except ValueError as exc:
        raise ValueError(f'Invalid {key}: {raw_value!r}') from exc
    if parsed <= 0:
        raise ValueError(f'{key} must be > 0, got {parsed}')
    return parsed


def _require_non_empty(raw: dict[str, str], key: str, default: str) -> str:
    value = raw.get(key, default)
    if not value:
        raise ValueError(f'{key} must not be empty')
    return value


def _parse_extra_certs(raw_value: str) -> tuple[tuple[str, Path], ...]:
    """Parse comma-separated name:path pairs from the CERTS env variable."""
    items: list[tuple[str, Path]] = []
    for entry in raw_value.split(','):
        cleaned = entry.strip()
        if not cleaned:
            continue
        if ':' not in cleaned:
            raise ValueError(f'Invalid CERTS entry {cleaned!r}: expected name:path')
        name, path_str = cleaned.split(':', 1)
        clean_name = name.strip()
        clean_path = path_str.strip()
        if not clean_name or not clean_path:
            raise ValueError(f'Invalid CERTS entry {cleaned!r}: empty name or path')
        items.append((clean_name, Path(clean_path)))
    return tuple(items)


def load_env(path: Path) -> dict[str, str]:
    """Parse a simple KEY=VALUE env file."""
    result: dict[str, str] = {}
    if not path.is_file():
        logger.warning('Env file %s not found, using defaults', path)
        return result

    for raw_line in path.read_text(encoding='utf-8').splitlines():
        line = raw_line.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        key, value = line.split('=', 1)
        cleaned_key = key.strip()
        if not cleaned_key:
            continue
        result[cleaned_key] = _strip_quotes(value.strip())

    return result


def load_config(path: Path = ENV_PATH) -> Config:
    """Load and validate daemon configuration from an env file."""
    defaults = Config()
    raw = load_env(path)

    raw_port = raw.get('MQTT_PORT', str(defaults.mqtt_port))
    try:
        mqtt_port = int(raw_port)
    except ValueError as exc:
        raise ValueError(f'Invalid MQTT_PORT: {raw_port!r}') from exc
    if not 1 <= mqtt_port <= MAX_MQTT_PORT:
        raise ValueError(f'MQTT_PORT must be between 1 and {MAX_MQTT_PORT}, got {mqtt_port}')

    publish_interval_sec = _parse_positive_float(raw, 'PUBLISH_INTERVAL_SEC', defaults.publish_interval_sec)
    alert_threshold_days = _parse_positive_float(raw, 'ALERT_THRESHOLD_DAYS', defaults.alert_threshold_days)
    topic_base = raw.get('TOPIC', defaults.topic_base).rstrip('/')
    if not topic_base:
        raise ValueError('TOPIC must not be empty')

    broker = _require_non_empty(raw, 'BROKER', defaults.broker)
    client_id = _require_non_empty(raw, 'CLIENT_ID', defaults.client_id)

    systemd_raw = raw.get('SYSTEMD_DIR', '').strip()
    systemd_dir = Path(systemd_raw) if systemd_raw else defaults.systemd_dir
    extra_certs = _parse_extra_certs(raw.get('CERTS', ''))

    return Config(
        broker=broker,
        mqtt_port=mqtt_port,
        mqtt_cafile=raw.get('MQTT_CAFILE', defaults.mqtt_cafile),
        mqtt_cert=raw.get('MQTT_CERT', defaults.mqtt_cert),
        mqtt_key=raw.get('MQTT_KEY', defaults.mqtt_key),
        topic_base=topic_base,
        client_id=client_id,
        publish_interval_sec=publish_interval_sec,
        systemd_dir=systemd_dir,
        extra_certs=extra_certs,
        alert_threshold_days=alert_threshold_days,
    )


def _read_cert_path_from_override(override_file: Path) -> Path | None:
    """Extract Environment=CERT_PATH=... from a systemd service drop-in."""
    if not override_file.is_file():
        return None
    try:
        lines = override_file.read_text(encoding='utf-8').splitlines()
    except OSError as exc:
        logger.warning('Failed to read %s: %s', override_file, exc)
        return None
    for raw_line in lines:
        line = raw_line.strip()
        if line.startswith(CERT_PATH_PREFIX):
            raw_path = _strip_quotes(line.removeprefix(CERT_PATH_PREFIX).strip())
            return Path(raw_path) if raw_path else None
    return None


def discover_profile_certs(
    systemd_dir: Path = DEFAULT_SYSTEMD_DIR,
    extra_certs: tuple[tuple[str, Path], ...] = (),
) -> tuple[CertProfile, ...]:
    """Discover certificates from enabled cert-renewer timers and extra config entries.

    Enabled timers whose service drop-in lacks ``CERT_PATH`` are still returned (with ``cert_path=None``)
    so they surface as unreadable instead of silently dropping out of monitoring.
    """
    discovered: dict[str, Path | None] = {}
    wants_dir = systemd_dir / 'timers.target.wants'
    if wants_dir.is_dir():
        for entry in sorted(wants_dir.iterdir(), key=lambda p: p.name):
            if not (entry.name.startswith(TIMER_PREFIX) and entry.name.endswith(TIMER_SUFFIX)):
                continue
            profile_name = entry.name.removeprefix(TIMER_PREFIX).removesuffix(TIMER_SUFFIX)
            override_file = systemd_dir / f'{TIMER_PREFIX}{profile_name}.service.d' / 'override.conf'
            cert_path = _read_cert_path_from_override(override_file)
            if cert_path is None:
                logger.warning(
                    'Enabled timer %s has no %s in %s; reporting it as unreadable',
                    entry.name,
                    CERT_PATH_PREFIX,
                    override_file,
                )
            discovered[profile_name] = cert_path

    discovered.update(dict(extra_certs))

    return tuple(CertProfile(name=name, cert_path=discovered[name]) for name in sorted(discovered))


def _extract_leaf_der(pem_text: str) -> bytes:
    start = pem_text.find(PEM_CERT_BEGIN)
    if start == -1:
        raise ValueError('Missing PEM certificate BEGIN marker')
    body_start = start + len(PEM_CERT_BEGIN)
    end = pem_text.find(PEM_CERT_END, body_start)
    if end == -1:
        raise ValueError('Missing PEM certificate END marker')
    b64_payload = ''.join(pem_text[body_start:end].split())
    if not b64_payload:
        raise ValueError('Empty PEM certificate payload')
    return base64.b64decode(b64_payload, validate=True)


def _read_der_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    if offset >= len(data):
        raise ValueError('Unexpected end of DER data')
    tag = data[offset]
    idx = offset + 1
    if idx >= len(data):
        raise ValueError('Truncated DER length byte')
    first_len = data[idx]
    idx += 1
    if first_len < DER_LONG_FORM_BIT:
        length = first_len
    else:
        num_octets = first_len & DER_LONG_FORM_MASK
        if num_octets == 0 or idx + num_octets > len(data):
            raise ValueError('Invalid DER length encoding')
        length = int.from_bytes(data[idx : idx + num_octets], 'big')
        idx += num_octets
    end = idx + length
    if end > len(data):
        raise ValueError('DER value exceeds buffer length')
    return tag, data[idx:end], end


def _parse_asn1_time(tag: int, raw: bytes) -> datetime:
    text = raw.decode('ascii')
    if tag == DER_UTC_TIME_TAG:
        yy = int(text[:2])
        year = (UTC_TIME_CENTURY_1900 if yy >= UTC_TIME_PIVOT_YEAR else UTC_TIME_CENTURY_2000) + yy
        return datetime.strptime(f'{year:04d}{text[2:]}', '%Y%m%d%H%M%S%z')
    if tag == DER_GENERALIZED_TIME_TAG:
        return datetime.strptime(text, '%Y%m%d%H%M%S%z')
    raise ValueError(f'Unsupported ASN.1 time tag: {tag:#x}')


def _parse_cert_not_after(cert_path: Path) -> datetime:
    der = _extract_leaf_der(cert_path.read_text(encoding='utf-8'))
    cert_tag, cert_body, _ = _read_der_tlv(der, 0)
    if cert_tag != DER_SEQUENCE_TAG:
        raise ValueError(f'Expected Certificate SEQUENCE, got {cert_tag:#x}')

    tbs_tag, tbs_body, _ = _read_der_tlv(cert_body, 0)
    if tbs_tag != DER_SEQUENCE_TAG:
        raise ValueError(f'Expected TBSCertificate SEQUENCE, got {tbs_tag:#x}')

    tag, _val, pos = _read_der_tlv(tbs_body, 0)
    if tag == DER_EXPLICIT_VERSION_TAG:
        _tag, _val, pos = _read_der_tlv(tbs_body, pos)  # serialNumber
    _tag, _val, pos = _read_der_tlv(tbs_body, pos)  # signature
    _tag, _val, pos = _read_der_tlv(tbs_body, pos)  # issuer
    val_tag, val_body, _ = _read_der_tlv(tbs_body, pos)  # validity
    if val_tag != DER_SEQUENCE_TAG:
        raise ValueError(f'Expected Validity SEQUENCE, got {val_tag:#x}')

    _nb_tag, _nb_val, pos = _read_der_tlv(val_body, 0)  # notBefore
    na_tag, na_val, _ = _read_der_tlv(val_body, pos)  # notAfter
    return _parse_asn1_time(na_tag, na_val)


@dataclass(frozen=True)
class CertSample:
    """Detailed certificate expiry sample."""

    days_left: float | None
    expired: bool = False
    error: str | None = None


class CertExpiryTracker:
    """Track remaining certificate validity days with mtime-aware caching."""

    def __init__(self, cert_path: Path | None, refresh_interval_sec: float = CERT_REFRESH_INTERVAL_SEC) -> None:
        """Initialize the tracker with certificate path and cache refresh interval."""
        self.cert_path = cert_path
        self.refresh_interval_sec = refresh_interval_sec
        self._not_after: datetime | None = None
        self._last_refresh_monotonic: float | None = None
        self._last_file_sig: tuple[int, int] | None = None
        self._warned_missing = False
        self._last_error: str | None = None

    def _read_signature(self) -> tuple[int, int] | None:
        if self.cert_path is None:
            return None
        try:
            st = self.cert_path.stat()
        except OSError:
            return None
        return (st.st_mtime_ns, st.st_size)

    def _refresh(self, current_mono: float, sig: tuple[int, int] | None) -> None:
        self._last_refresh_monotonic = current_mono
        self._last_file_sig = sig
        self._not_after = None
        if self.cert_path is None:
            self._last_error = CERT_ERROR_NO_CERT_PATH
            return
        if sig is None or not self.cert_path.is_file():
            if not self._warned_missing:
                logger.warning('Certificate %s not found, metric unavailable', self.cert_path)
                self._warned_missing = True
            self._last_error = CERT_ERROR_MISSING
            return

        try:
            self._not_after = _parse_cert_not_after(self.cert_path)
            self._warned_missing = False
            self._last_error = None
        except (OSError, ValueError) as exc:
            logger.error('Failed to parse certificate expiry from %s: %s', self.cert_path, exc)
            self._last_error = CERT_ERROR_PARSE

    def sample_detail(self, *, now_monotonic: float | None = None, now_utc: datetime | None = None) -> CertSample:
        """Return remaining days (rounded, clamped to zero), raw expiry flag, and read error reason."""
        current_mono = time.monotonic() if now_monotonic is None else now_monotonic
        sig = self._read_signature()
        interval_elapsed = (
            self._last_refresh_monotonic is None
            or (current_mono - self._last_refresh_monotonic) >= self.refresh_interval_sec
        )
        if sig != self._last_file_sig or interval_elapsed:
            self._refresh(current_mono, sig)

        if self._not_after is None:
            return CertSample(days_left=None, error=self._last_error or CERT_ERROR_MISSING)

        current_utc = datetime.now(UTC) if now_utc is None else now_utc
        remaining_days = (self._not_after - current_utc).total_seconds() / SECONDS_PER_DAY
        return CertSample(days_left=round(max(remaining_days, 0.0), 1), expired=self._not_after <= current_utc)

    def sample(self, *, now_monotonic: float | None = None, now_utc: datetime | None = None) -> float | None:
        """Return remaining days until certificate expiry, clamped to zero."""
        return self.sample_detail(now_monotonic=now_monotonic, now_utc=now_utc).days_left


class LastSeenTracker:
    """Rate-limit UTC last_seen ISO 8601 timestamps to protect Home Assistant Recorder."""

    def __init__(self, refresh_interval_sec: float = LAST_SEEN_INTERVAL_SEC) -> None:
        """Initialize timestamp cache and minimum refresh interval."""
        self.refresh_interval_sec = refresh_interval_sec
        self._last_updated: float | None = None
        self._cached_iso: str | None = None

    def sample(self) -> str:
        """Return cached UTC ISO 8601 timestamp, refreshing at most once per interval."""
        now_mono = time.monotonic()
        if (
            self._cached_iso is None
            or self._last_updated is None
            or (now_mono - self._last_updated) >= self.refresh_interval_sec
        ):
            self._cached_iso = datetime.now(UTC).isoformat(timespec='seconds')
            self._last_updated = now_mono
        return self._cached_iso


@dataclass(frozen=True)
class MonitoredCert:
    """Certificate profile paired with its expiry tracker."""

    profile: CertProfile
    tracker: CertExpiryTracker


def _build_alert_summary(
    samples: list[tuple[CertProfile, CertSample]],
    threshold_days: float,
) -> dict[str, object]:
    """Aggregate per-certificate samples into the summary published under the `alert` key."""
    expiring: list[tuple[float, str, dict[str, object]]] = []
    unreadable: list[tuple[str, dict[str, object]]] = []
    all_certs: dict[str, dict[str, object]] = {}
    readable_days: list[float] = []

    for profile, sample in samples:
        all_certs[profile.slug] = {'name': profile.display_name, 'days_left': sample.days_left}
        if sample.days_left is None:
            reason = sample.error or CERT_ERROR_MISSING
            unreadable.append((profile.slug, {'slug': profile.slug, 'name': profile.display_name, 'reason': reason}))
            continue
        readable_days.append(sample.days_left)
        if sample.days_left < threshold_days:
            entry: dict[str, object] = {
                'slug': profile.slug,
                'name': profile.display_name,
                'days_left': sample.days_left,
                'expired': sample.expired,
            }
            expiring.append((sample.days_left, profile.slug, entry))

    expiring.sort(key=lambda item: (item[0], item[1]))
    unreadable.sort(key=lambda item: item[0])
    return {
        'expiring_soon': bool(expiring or unreadable or not samples),
        'threshold_days': threshold_days,
        'profiles_count': len(samples),
        'expiring_count': len(expiring) + len(unreadable),
        'min_days_left': min(readable_days, default=None),
        'expiring': [entry for _days, _slug, entry in expiring],
        'unreadable': [entry for _slug, entry in unreadable],
        'all_certs': all_certs,
    }


def collect_metrics(
    monitored: tuple[MonitoredCert, ...],
    last_seen_tracker: LastSeenTracker,
    alert_threshold_days: float = DEFAULT_ALERT_THRESHOLD_DAYS,
) -> dict[str, object]:
    """Collect certificate remaining days, alert summary, and last_seen timestamp into one JSON payload."""
    payload: dict[str, object] = {'last_seen': last_seen_tracker.sample()}
    samples: list[tuple[CertProfile, CertSample]] = []
    for item in monitored:
        sample = item.tracker.sample_detail()
        samples.append((item.profile, sample))
        if sample.days_left is not None:
            payload[f'{item.profile.slug}_days_left'] = sample.days_left
    payload['alert'] = _build_alert_summary(samples, alert_threshold_days)
    return payload


def _reason_is_failure(reason_code: ReasonCode | int) -> bool:
    if hasattr(reason_code, 'is_failure'):
        return bool(reason_code.is_failure)
    return reason_code != 0


def on_connect(
    client: mqtt.Client,
    userdata: MonitorContext | None,
    flags: ConnectFlags,
    reason_code: ReasonCode | int,
    properties: Properties | None = None,
) -> None:
    """MQTT on_connect callback (Callback API v2)."""
    del flags, properties
    logger.info('MQTT connected: rc=%s', reason_code)
    if _reason_is_failure(reason_code):
        logger.error('MQTT connection failed: %s', reason_code)
        return

    context = userdata if isinstance(userdata, MonitorContext) else MonitorContext(config=Config(), profiles=())
    publish_discovery(client, context.config, context.profiles)
    client.publish(f'{context.config.topic_base}/availability', payload='online', qos=1, retain=True)


def on_disconnect(
    client: mqtt.Client,
    userdata: MonitorContext | None,
    disconnect_flags: DisconnectFlags,
    reason_code: ReasonCode | int,
    properties: Properties | None = None,
) -> None:
    """MQTT on_disconnect callback (Callback API v2)."""
    del client, userdata, disconnect_flags, properties
    if _reason_is_failure(reason_code):
        logger.warning('MQTT disconnected unexpectedly: rc=%s', reason_code)
    else:
        logger.info('MQTT disconnected cleanly: rc=%s', reason_code)


def _discovery_topic(topic_base: str, component: str, object_id: str) -> str:
    """Build Home Assistant MQTT Discovery config topic for a component."""
    if component == 'sensor':
        return f'{topic_base}/{object_id}/config'
    if '/sensor/' in topic_base:
        component_base = topic_base.replace('/sensor/', f'/{component}/', 1)
        return f'{component_base}/{object_id}/config'
    if topic_base.startswith('sensor/'):
        component_base = f'{component}/{topic_base.removeprefix("sensor/")}'
        return f'{component_base}/{object_id}/config'
    return f'{topic_base}/{component}/{object_id}/config'


def _build_cert_sensor_spec(profile: CertProfile) -> SensorSpec:
    """Build a SensorSpec for a discovered cert-renewer profile."""
    json_key = f'{profile.slug}_days_left'
    return SensorSpec(
        object_id=json_key,
        json_key=json_key,
        name=f'{profile.display_name} Cert Days Left',
        unique_id=f'homelab_certs_{json_key}',
        unit_of_measurement='d',
        state_class='measurement',
        device_class='duration',
        icon='mdi:certificate-outline',
        entity_category=None,
    )


def _apply_common_discovery_fields(
    cfg: dict[str, object],
    spec: SensorSpec | BinarySensorSpec,
    config: Config,
) -> None:
    """Populate optional metadata, availability, and expiry fields on a discovery payload."""
    if spec.device_class is not None:
        cfg['device_class'] = spec.device_class
    if spec.icon is not None:
        cfg['icon'] = spec.icon
    if spec.entity_category is not None:
        cfg['entity_category'] = spec.entity_category
    if spec.use_availability:
        cfg['availability_topic'] = f'{config.topic_base}/availability'
        cfg['payload_available'] = 'online'
        cfg['payload_not_available'] = 'offline'
    if spec.use_expire_after:
        cfg['expire_after'] = max(int(config.publish_interval_sec * EXPIRE_MULTIPLIER), MIN_EXPIRE_AFTER_SEC)


def _build_sensor_payload(sensor: SensorSpec, config: Config) -> dict[str, object]:
    """Build Home Assistant MQTT Discovery payload for a sensor entity."""
    cfg: dict[str, object] = {
        'name': sensor.name,
        'state_topic': f'{config.topic_base}/state',
        'value_template': (
            f'{{{{ value_json.{sensor.json_key} '
            f'if value_json.{sensor.json_key} is defined '
            f'and value_json.{sensor.json_key} is not none '
            f'else this.state }}}}'
        ),
        'unique_id': sensor.unique_id,
        'device': DEVICE_JSON,
    }
    if sensor.unit_of_measurement is not None:
        cfg['unit_of_measurement'] = sensor.unit_of_measurement
    if sensor.state_class is not None:
        cfg['state_class'] = sensor.state_class
    _apply_common_discovery_fields(cfg, sensor, config)
    return cfg


def _build_binary_sensor_payload(sensor: BinarySensorSpec, config: Config) -> dict[str, object]:
    """Build Home Assistant MQTT Discovery payload for a binary_sensor entity."""
    cfg: dict[str, object] = {
        'name': sensor.name,
        'state_topic': f'{config.topic_base}/{sensor.state_topic_suffix}',
        'payload_on': sensor.payload_on,
        'payload_off': sensor.payload_off,
        'unique_id': sensor.unique_id,
        'device': DEVICE_JSON,
    }
    if sensor.value_template is not None:
        cfg['value_template'] = sensor.value_template
    if sensor.json_attributes_template is not None:
        cfg['json_attributes_topic'] = f'{config.topic_base}/state'
        cfg['json_attributes_template'] = sensor.json_attributes_template
    _apply_common_discovery_fields(cfg, sensor, config)
    return cfg


def publish_discovery(
    client: mqtt.Client,
    config: Config,
    profiles: tuple[CertProfile, ...],
) -> None:
    """Publish Home Assistant MQTT Discovery configs (retained)."""
    logger.info('Publishing Home Assistant discovery configs for %d profile(s)', len(profiles))
    sensors = (LAST_SEEN_SENSOR, *(_build_cert_sensor_spec(profile) for profile in profiles))
    for sensor in sensors:
        client.publish(
            _discovery_topic(config.topic_base, 'sensor', sensor.object_id),
            payload=json.dumps(_build_sensor_payload(sensor, config)),
            retain=True,
        )

    for binary_sensor in (STATUS_BINARY_SENSOR, EXPIRING_SOON_BINARY_SENSOR):
        client.publish(
            _discovery_topic(config.topic_base, 'binary_sensor', binary_sensor.object_id),
            payload=json.dumps(_build_binary_sensor_payload(binary_sensor, config)),
            retain=True,
        )


def create_mqtt_client(context: MonitorContext) -> mqtt.Client:
    """Create and configure the MQTT client with TLS, mTLS, LWT, and Callback API v2."""
    cfg = context.config
    client = mqtt.Client(
        callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
        client_id=cfg.client_id,
        protocol=mqtt.MQTTv5,
        userdata=context,
    )
    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.will_set(f'{cfg.topic_base}/availability', payload='offline', qos=1, retain=True)

    client.tls_set(
        ca_certs=cfg.mqtt_cafile,
        certfile=cfg.mqtt_cert,
        keyfile=cfg.mqtt_key,
        cert_reqs=ssl.CERT_REQUIRED,
        tls_version=ssl.PROTOCOL_TLS_CLIENT,
    )
    client.tls_insecure_set(value=False)
    client.reconnect_delay_set(min_delay=1, max_delay=30)
    return client


def _install_signal_handlers(stop_event: threading.Event) -> None:
    def _handle_signal(signum: int, _frame: FrameType | None) -> None:
        logger.info('Received signal %s, shutting down...', signum)
        stop_event.set()

    for sig_name in ('SIGINT', 'SIGTERM'):
        sig = getattr(signal, sig_name, None)
        if sig is None:
            continue
        with contextlib.suppress(ValueError):
            signal.signal(sig, _handle_signal)


def main(config: Config | None = None, stop_event: threading.Event | None = None) -> None:
    """Connect to MQTT and periodically publish certificate expiry metrics."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
    )

    cfg = load_config(ENV_PATH) if config is None else config
    event = threading.Event() if stop_event is None else stop_event
    _install_signal_handlers(event)

    profiles = discover_profile_certs(cfg.systemd_dir, cfg.extra_certs)
    logger.info(
        'Starting cert monitor, broker=%s:%d, topic_base=%s, alert_threshold_days=%s, profiles=%s',
        cfg.broker,
        cfg.mqtt_port,
        cfg.topic_base,
        cfg.alert_threshold_days,
        [p.name for p in profiles],
    )
    if not profiles:
        logger.warning('No certificate profiles discovered; reporting expiring_soon=ON')

    monitored = tuple(MonitoredCert(profile, CertExpiryTracker(profile.cert_path)) for profile in profiles)
    last_seen_tracker = LastSeenTracker()
    client = create_mqtt_client(MonitorContext(config=cfg, profiles=profiles))
    client.connect_async(cfg.broker, cfg.mqtt_port, keepalive=MQTT_KEEPALIVE_SEC)
    client.loop_start()

    try:
        while not event.is_set():
            try:
                payload = collect_metrics(monitored, last_seen_tracker, cfg.alert_threshold_days)
                if payload and client.is_connected():
                    info = client.publish(
                        f'{cfg.topic_base}/state',
                        payload=json.dumps(payload),
                        retain=False,
                    )
                    if info.rc != mqtt.MQTT_ERR_SUCCESS:
                        logger.warning('Failed to publish MQTT state message: rc=%s', info.rc)
            except (OSError, ValueError, RuntimeError):
                logger.exception('Unexpected error in main loop')
            event.wait(cfg.publish_interval_sec)
    finally:
        if client.is_connected():
            client.publish(f'{cfg.topic_base}/availability', payload='offline', qos=1, retain=True)
        client.disconnect()
        client.loop_stop()
        logger.info('Cert monitor stopped cleanly')


if __name__ == '__main__':
    main()
