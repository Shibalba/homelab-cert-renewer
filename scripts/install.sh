#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SYSTEMD_DIR="/etc/systemd/system"
STEP_BIN="${STEP_BIN:-/usr/bin/step}"
STEP_ROOT_CA="${STEP_ROOT_CA:-/etc/step/root_ca.crt}"
CA_HOST="${CA_HOST:-step.local}"

DRY_RUN=false
PROFILES=()
DIFF_FOUND=false
SERVICE_USER="${SUDO_USER:-}"
SERVICE_HOME=""
RENDER_DIR=""

usage() {
    cat <<'EOF'
Usage: sudo ./scripts/install.sh [--dry-run] [--user <name>] <profile>...

Install cert-renewer systemd templates and selected profile overrides.

Profile files may contain placeholders that are rendered at install time:
  @SERVICE_USER@  service account owning the certificates (from --user, default: $SUDO_USER)
  @SERVICE_HOME@  home directory of that account (from getent passwd)

Options:
  --dry-run      Compare rendered files against /etc/systemd/system without modifying anything.
  --user <name>  Service account for @SERVICE_USER@/@SERVICE_HOME@ (default: the user who invoked sudo).
  -h, --help     Show this help message.

Examples:
  sudo ./scripts/install.sh --dry-run rpi-stats zigbee2mqtt
  sudo ./scripts/install.sh rpi-stats zigbee2mqtt
  sudo ./scripts/install.sh --user pi rpi-stats zigbee2mqtt
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --user)
            if [[ $# -lt 2 || -z "$2" ]]; then
                echo "Error: --user requires a value." >&2
                exit 2
            fi
            SERVICE_USER="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        -*)
            echo "Error: unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
        *)
            PROFILES+=("$1")
            shift
            ;;
    esac
done

if [[ ${#PROFILES[@]} -eq 0 ]]; then
    echo "Error: at least one profile name is required." >&2
    usage >&2
    exit 2
fi

if [[ ${EUID} -ne 0 ]]; then
    echo "Error: please run with sudo (required to manage ${SYSTEMD_DIR} and check 0600 certs)." >&2
    exit 1
fi

resolve_service_user() {
    local passwd_entry
    if [[ -z "${SERVICE_USER}" || "${SERVICE_USER}" == 'root' ]]; then
        echo "Error: cannot determine the service account; pass --user <name>." >&2
        exit 2
    fi
    if [[ ! "${SERVICE_USER}" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
        echo "Error: invalid user name '${SERVICE_USER}'." >&2
        exit 2
    fi
    if ! passwd_entry="$(getent passwd "${SERVICE_USER}")"; then
        echo "Error: user '${SERVICE_USER}' does not exist." >&2
        exit 1
    fi
    SERVICE_HOME="$(printf '%s' "${passwd_entry}" | cut -d: -f6)"
    if [[ ! "${SERVICE_HOME}" =~ ^/[A-Za-z0-9._/-]*$ ]]; then
        echo "Error: unsupported home directory '${SERVICE_HOME}' for user '${SERVICE_USER}'." >&2
        exit 1
    fi
}

render_file() {
    local src="$1"
    local dst="$2"
    install -d -m 0755 "$(dirname "${dst}")"
    sed -e "s|@SERVICE_USER@|${SERVICE_USER}|g" -e "s|@SERVICE_HOME@|${SERVICE_HOME}|g" "${src}" > "${dst}"
    if grep -q '@SERVICE_[A-Z]*@' "${dst}"; then
        echo "Error: unknown placeholder left in ${src}." >&2
        exit 1
    fi
}

render_profile() {
    local profile="$1"
    local profile_dir="${REPO_ROOT}/profiles/${profile}"
    local name

    if [[ ! -f "${profile_dir}/service.conf" ]]; then
        echo "Error: profile '${profile}' missing ${profile_dir}/service.conf." >&2
        exit 1
    fi
    for name in service.conf timer.conf; do
        if [[ -f "${profile_dir}/${name}" ]]; then
            render_file "${profile_dir}/${name}" "${RENDER_DIR}/${profile}/${name}"
        fi
    done
}

check_prerequisites() {
    if ! command -v systemctl >/dev/null 2>&1; then
        echo "Error: systemctl not found." >&2
        exit 1
    fi
    if [[ ! -x "${STEP_BIN}" ]]; then
        echo "Error: step CLI not found or not executable at ${STEP_BIN}." >&2
        exit 1
    fi
    if [[ ! -f "${STEP_ROOT_CA}" ]]; then
        echo "Error: Root CA file not found at ${STEP_ROOT_CA}." >&2
        echo "Hint: sudo install -d -m 0755 /etc/step && sudo install -m 0644 ~/.step/certs/root_ca.crt ${STEP_ROOT_CA}" >&2
        exit 1
    fi
    if ! getent hosts "${CA_HOST}" >/dev/null 2>&1; then
        echo "Error: host '${CA_HOST}' does not resolve." >&2
        echo "Hint: add '<CA_IP> ${CA_HOST}' to /etc/hosts." >&2
        exit 1
    fi
}

extract_env_var() {
    local file="$1"
    local var_name="$2"
    local line prefix
    prefix="Environment=${var_name}="
    line="$(grep -E "^${prefix}" "${file}" | head -n 1 || true)"
    printf '%s' "${line#"${prefix}"}"
}

check_profile() {
    local profile="$1"
    local service_conf="${RENDER_DIR}/${profile}/service.conf"
    local cert_path key_path

    cert_path="$(extract_env_var "${service_conf}" 'CERT_PATH')"
    key_path="$(extract_env_var "${service_conf}" 'KEY_PATH')"

    if [[ -z "${cert_path}" || -z "${key_path}" ]]; then
        echo "Error: ${service_conf} must define Environment=CERT_PATH=... and Environment=KEY_PATH=...." >&2
        exit 1
    fi
    if [[ ! -f "${cert_path}" || ! -f "${key_path}" ]]; then
        echo "Error: certificate/key missing for profile '${profile}': ${cert_path}, ${key_path}" >&2
        echo "Hint: issue the initial 30-day certificate first using ./scripts/issue-cert.sh" >&2
        exit 1
    fi
}

sync_file() {
    local src="$1"
    local dst="$2"

    if [[ "${DRY_RUN}" == true ]]; then
        if [[ ! -f "${dst}" ]]; then
            echo "[dry-run] WOULD CREATE: ${dst} (from ${src})"
            DIFF_FOUND=true
        elif ! cmp -s "${src}" "${dst}"; then
            echo "[dry-run] DIFFERS: ${dst}"
            diff -u "${dst}" "${src}" || true
            DIFF_FOUND=true
        else
            echo "[dry-run] OK (identical): ${dst}"
        fi
        return 0
    fi

    install -d -m 0755 "$(dirname "${dst}")"
    install -m 0644 "${src}" "${dst}"
    echo "Installed: ${dst}"
}

check_prerequisites
resolve_service_user
RENDER_DIR="$(mktemp -d)"
trap 'rm -rf "${RENDER_DIR}"' EXIT
echo "Service account: ${SERVICE_USER} (home: ${SERVICE_HOME})"
for profile in "${PROFILES[@]}"; do
    render_profile "${profile}"
    check_profile "${profile}"
done

sync_file "${REPO_ROOT}/systemd/cert-renewer@.service" "${SYSTEMD_DIR}/cert-renewer@.service"
sync_file "${REPO_ROOT}/systemd/cert-renewer@.timer" "${SYSTEMD_DIR}/cert-renewer@.timer"

for profile in "${PROFILES[@]}"; do
    rendered_dir="${RENDER_DIR}/${profile}"
    sync_file "${rendered_dir}/service.conf" "${SYSTEMD_DIR}/cert-renewer@${profile}.service.d/override.conf"
    if [[ -f "${rendered_dir}/timer.conf" ]]; then
        sync_file "${rendered_dir}/timer.conf" "${SYSTEMD_DIR}/cert-renewer@${profile}.timer.d/override.conf"
    fi
done

if [[ "${DRY_RUN}" == true ]]; then
    if [[ "${DIFF_FOUND}" == true ]]; then
        echo "Dry-run completed: changes detected."
    else
        echo "Dry-run completed: all installed files match repository."
    fi
    exit 0
fi

systemctl daemon-reload
for profile in "${PROFILES[@]}"; do
    systemctl enable --now "cert-renewer@${profile}.timer"
    echo "Enabled timer: cert-renewer@${profile}.timer"
done
