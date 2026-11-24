# Homelab Cert Renewer

Lightweight `systemd` templates, service profiles, and helper scripts for passwordless 30-day (`720h`) certificate auto-renewal against a **Smallstep CA (`step-ca`)** on **Raspberry Pi OS** (Debian 12 Bookworm), with an optional Home Assistant MQTT certificate expiry monitor.

## How It Works

1. Initial 30-day certificates are issued once with `./scripts/issue-cert.sh` (requires the JWK provisioner password once).
2. A daily `cert-renewer@<profile>.timer` triggers `cert-renewer@<profile>.service`.
3. `ExecCondition` runs `step certificate needs-renewal ${CERT_PATH} --expires-in 33%`:
   - Days 1–19: exits silently with `0` disk writes and `0` service restarts.
   - Days 20–30: runs `step ca renew --force` over mTLS (no password needed), restores owner/mode via `ExecStartPost`, and reloads/restarts the target service.

Consumes **0 MiB RAM** when idle (unlike `step ca renew --daemon`).

## Repository Layout

```text
homelab-cert-renewer/
├─ systemd/
│  ├─ cert-renewer@.service       # Generic Smallstep renewer template
│  ├─ cert-renewer@.timer         # Daily timer (with 1h randomized delay)
│  └─ cert-monitor@.service       # Optional MQTT expiry monitor service (User=%i)
├─ profiles/
│  ├─ rpi-stats/service.conf      # rpi_stats_daemon@<user>.service
│  ├─ zigbee2mqtt/
│  │  ├─ service.conf             # zigbee2mqtt.service
│  │  └─ timer.conf               # Night window (03:30 + 30m randomized delay)
│  ├─ cert-monitor/service.conf   # cert-monitor@<user>.service (self-renewal)
│  └─ mosquitto/service.conf      # Broker template (SIGHUP reload, not enabled by default)
├─ config/
│  └─ cert_monitor.env.example    # Example /etc/cert_monitor.env (no secrets)
├─ src/
│  └─ cert_monitor.py             # Optional MQTT v5 + mTLS expiry monitor daemon
├─ tests/
│  └─ test_cert_monitor.py        # Pytest suite
├─ scripts/
│  ├─ install.sh                  # Idempotent systemd renewer installer & --dry-run diff checker
│  ├─ install-monitor.sh          # Optional MQTT monitor installer (uv + cert-monitor@.service)
│  └─ issue-cert.sh               # One-time 720h certificate issuer with backup
└─ .github/workflows/ci.yml       # shellcheck, LF, secret scan, ruff, pytest, uv audit, systemd verify
```

## Prerequisites on Raspberry Pi OS

1. `step` CLI installed at `/usr/bin/step`.
2. System Root CA present at `/etc/step/root_ca.crt` (`0644`):
   ```bash
   sudo install -d -m 0755 /etc/step
   sudo install -m 0644 ~/.step/certs/root_ca.crt /etc/step/root_ca.crt
   ```
3. `step.local` resolves cleanly (on Debian with mDNS `.local` interception, add `<CA_IP> step.local` to `/etc/hosts`).

## Installation (Core Auto-Renewal)

```bash
sudo mkdir -p /opt/homelab-cert-renewer
sudo chown <user>:<user> /opt/homelab-cert-renewer
git clone https://github.com/Shibalba/homelab-cert-renewer.git /opt/homelab-cert-renewer
cd /opt/homelab-cert-renewer
```

Issue an initial 30-day certificate if the service does not have one yet:

```bash
./scripts/issue-cert.sh rpi-stats \
  /etc/mosquitto/certs/rpi_stats.crt \
  /etc/mosquitto/certs/rpi_stats.key \
  <user>:<user> 0600
```

Preview changes against `/etc/systemd/system/` before installing:

```bash
sudo ./scripts/install.sh --dry-run rpi-stats zigbee2mqtt
```

Install templates, selected profile overrides, and enable timers:

```bash
sudo ./scripts/install.sh rpi-stats zigbee2mqtt
```

Profile files are templates: `@SERVICE_USER@` (owner of the certificates and the `rpi_stats_daemon@` / `cert-monitor@` instance) and `@SERVICE_HOME@` (that user's home directory) are rendered at install time. The account defaults to the user who invoked `sudo`; override it with `--user <name>`. `--dry-run` compares the rendered result.

## Optional: Home Assistant MQTT Monitoring (`cert-monitor`)

If you want a dedicated **`Homelab Certificates`** device in Home Assistant tracking `days_left` for every enabled `cert-renewer@*.timer` profile (plus `Status` via LWT and `Last Seen`):

1. Issue a 30-day mTLS certificate for `cert-monitor` and enable its renewal timer:
   ```bash
   ./scripts/issue-cert.sh cert-monitor \
     /etc/mosquitto/certs/cert_monitor.crt \
     /etc/mosquitto/certs/cert_monitor.key \
     <user>:<user> 0600
   sudo ./scripts/install.sh rpi-stats zigbee2mqtt cert-monitor
   ```
2. Create `/etc/cert_monitor.env` from `config/cert_monitor.env.example` (`BROKER=...`, `MQTT_CERT=...`, `MQTT_KEY=...`).
3. Install the `.venv` (`uv sync --frozen --no-dev`) and enable `cert-monitor@<user>.service`:
   ```bash
   sudo ./scripts/install-monitor.sh <user>
   ```

The daemon detects certificate renewals automatically via file `mtime_ns` changes and publishes updates every `60s` (`PUBLISH_INTERVAL_SEC`).

After enabling a new `cert-renewer@<name>.timer`, restart `cert-monitor@<user>.service` — profiles are discovered at startup. Nothing needs to change in Home Assistant.

### `Expiring Soon` problem sensor

`binary_sensor.homelab_certificates_expiring_soon` (`device_class: problem`) aggregates all profiles. It is `on` when:

- any certificate has `days_left < ALERT_THRESHOLD_DAYS` (default `7`, strict comparison against the rounded value shown in the `*_days_left` sensors);
- any certificate is unreadable: file missing (`missing`), not parseable (`parse_error`), or the enabled timer's `override.conf` has no `CERT_PATH` (`no_cert_path`);
- no profiles were discovered at all (misconfigured `SYSTEMD_DIR` / no enabled timers).

It becomes `unavailable` when the daemon goes offline (LWT / `expire_after`). Attributes come from the `alert` object of the state payload: `threshold_days`, `profiles_count`, `expiring_count`, `min_days_left`, `expiring` (`[{slug, name, days_left, expired}]`), `unreadable` (`[{slug, name, reason}]`), `all_certs` (`{slug: {name, days_left}}`).

> **Threshold limitation:** `ALERT_THRESHOLD_DAYS` is absolute. With 30-day certificates renewed at `33%` remaining (~10 days, `--expires-in 33%`), the default `7` leaves ~3 days to investigate a failed renewal. Certificates with a very different lifetime (e.g. 24h or 90d) need a different threshold.

### Home Assistant Blueprint

[`blueprints/automation/homelab_cert_expiring.yaml`](blueprints/automation/homelab_cert_expiring.yaml) builds the alert automation on top of the sensor (Home Assistant `>= 2024.10`):

| Trigger | When | Action |
|---|---|---|
| `expiring` | `off → on`, held for `for_duration` (default 5 min); ignored after `unavailable/unknown` (HA or monitor restarts) | Persistent notification + `notify_actions` |
| `escalated` | `expiring_count` grows while already `on` | Same, prefixed with "new problem" |
| `reminder` | Daily at `reminder_time` (default `10:00`) while `on` for more than 1h | Same, prefixed with "reminder" |
| `recovered` | `on → off` for 1 min | No Telegram message; the notification is handled per `recovery_notification` (below) |
| `stale` | `unavailable/unknown` for `stale_duration` (default 2h) — dead-man switch | Separate persistent notification + `notify_actions` |
| `monitor_back` | Back from `unavailable/unknown` | No Telegram message; the stale notification is handled per `recovery_notification` |
| manual **Run actions** | — | Test summary of all certificates via `notify_actions` (no persistent notification) |

Alerts land in the Home Assistant notification center (**Settings → Notifications**). `recovery_notification` controls what happens there when the problem clears:

- `keep` (default) — leave the alert until you press **Dismiss**;
- `resolve` — replace its text with "✅ resolved at …" plus current expiry days, still kept until **Dismiss** (for `monitor_back` only when a stale alert was actually raised, so HA restarts do not create notifications);
- `dismiss` — remove it automatically.

Daily reminders and escalations re-create the notification if you dismissed it while the problem is still active.

Inside `notify_actions` use `{{ alert_title }}` and `{{ alert_message }}`, e.g.:

```yaml
- action: telegram_bot.send_message
  data:
    config_entry_id: <your telegram_bot entry id>
    title: "{{ alert_title }}"
    message: "{{ alert_message }}"
```

**Install:** for a public repository use **Settings → Automations & scenes → Blueprints → Import Blueprint** with the GitHub URL of the file (updates via **Re-import blueprint**). For a private repository copy the file to `/config/blueprints/automation/homelab-cert-renewer/homelab_cert_expiring.yaml` on the Home Assistant host and reload automations.

### Optional dynamic dashboard card (`auto-entities` from HACS)

```yaml
type: vertical-stack
cards:
  - type: entities
    title: Homelab Certificates
    show_header_toggle: false
    entities:
      - entity: binary_sensor.homelab_certificates_expiring_soon
        name: Expiring Soon
      - entity: binary_sensor.homelab_certificates_status
        name: Cert Monitor Status
      - entity: sensor.homelab_certificates_last_seen
        name: Last Seen
  - type: custom:auto-entities
    card:
      type: entities
      show_header_toggle: false
    filter:
      include:
        - device: Homelab Certificates
          entity_id: "sensor.*_days_left"
    sort:
      method: state
      numeric: true
```

## Verification

```bash
systemctl list-timers 'cert-renewer*' --no-pager
sudo systemctl start cert-renewer@rpi-stats.service
journalctl -u 'cert-renewer@*' -n 20 --no-pager
```

For fresh 30-day certificates, `journalctl` should report `certificate does not need renewal` and `Skipped due to 'exec-condition'`.

## Adding Another Service Profile

Create `profiles/<name>/service.conf` (copy an existing profile and adapt `CERT_PATH`, `KEY_PATH`, owner/mode, and the reload/restart command), optionally add `profiles/<name>/timer.conf`, then run:

```bash
sudo ./scripts/install.sh <name>
```
