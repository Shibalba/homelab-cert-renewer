#!/usr/bin/env bash
set -euo pipefail

STEP_BIN="${STEP_BIN:-/usr/bin/step}"
STEP_CA_URL="${STEP_CA_URL:-https://step.local:9000}"
STEP_ROOT_CA="${STEP_ROOT_CA:-/etc/step/root_ca.crt}"
NOT_AFTER="${NOT_AFTER:-720h}"

usage() {
    cat <<'EOF'
Usage: ./scripts/issue-cert.sh <CN> <cert_path> <key_path> [owner:group] [mode]

Issue a short-lived certificate (default 720h / 30 days) from Smallstep CA,
backing up any existing files with a timestamped .bak suffix.

Examples:
  ./scripts/issue-cert.sh rpi-stats /etc/mosquitto/certs/rpi_stats.crt /etc/mosquitto/certs/rpi_stats.key <user>:<user> 0600
  ./scripts/issue-cert.sh zigbee2mqtt /home/<user>/zigbee2mqtt/data/certs/client.crt /home/<user>/zigbee2mqtt/data/certs/client.key
EOF
}

if [[ "${1:-}" == '-h' || "${1:-}" == '--help' ]]; then
    usage
    exit 0
fi

if [[ $# -lt 3 || $# -gt 5 ]]; then
    usage >&2
    exit 2
fi

CN="$1"
CERT_PATH="$2"
KEY_PATH="$3"
OWNER="${4:-}"
MODE="${5:-0600}"

if [[ ! -x "${STEP_BIN}" ]]; then
    echo "Error: step CLI not found at ${STEP_BIN}." >&2
    exit 1
fi
if [[ ! -f "${STEP_ROOT_CA}" ]]; then
    echo "Error: Root CA not found at ${STEP_ROOT_CA}." >&2
    exit 1
fi

timestamp="$(date +%Y%m%d%H%M%S)"
for existing in "${CERT_PATH}" "${KEY_PATH}"; do
    if [[ -f "${existing}" ]]; then
        backup="${existing}.bak.${timestamp}"
        cp -p "${existing}" "${backup}"
        echo "Backed up: ${existing} -> ${backup}"
    fi
done

mkdir -p "$(dirname "${CERT_PATH}")" "$(dirname "${KEY_PATH}")"

"${STEP_BIN}" ca certificate "${CN}" "${CERT_PATH}" "${KEY_PATH}" \
    --ca-url "${STEP_CA_URL}" \
    --root "${STEP_ROOT_CA}" \
    --not-after="${NOT_AFTER}" \
    --force

chmod "${MODE}" "${CERT_PATH}" "${KEY_PATH}"
if [[ -n "${OWNER}" ]]; then
    chown "${OWNER}" "${CERT_PATH}" "${KEY_PATH}"
fi

echo "Issued certificate details:"
openssl x509 -in "${CERT_PATH}" -noout -subject -issuer -dates -serial -ext subjectAltName
