#!/usr/bin/env bash
#
# Validate or restore an archive produced by backup-production-data.sh.
#
# Usage:
#   ./scripts/restore-production-data.sh --dry-run ARCHIVE
#   ./scripts/restore-production-data.sh --confirm-restore ARCHIVE
#   ./scripts/restore-production-data.sh --confirm-restore --leave-stopped ARCHIVE
#
# The restore target is deliberately fixed to the three named production data
# volumes. Runtime environment files and encryption keys are never opened,
# copied, printed, or restored by this script.
set -euo pipefail
umask 077

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

PROJECT="composio-ops-prod"
ENV_FILE=".env.production"
DATA_VOLUME="${PROJECT}_ops_data"
VAULT_VOLUME="${PROJECT}_credential_vault"
BROWSER_VOLUME="${PROJECT}_browser_profiles"
SAFETY_DIR="${RESTORE_SAFETY_DIR:-$REPO_ROOT/restore-safety-backups}"
EVIDENCE_ROOT="${RESTORE_EVIDENCE_DIR:-$REPO_ROOT/restore-evidence}"
INPUT_STAGE_ROOT="$REPO_ROOT/restore-input-staging"
RELEASE_LOCK_PATH="$REPO_ROOT/backups/.production-operations.lock"
RELEASE_LOCK_FD=9
HELPER_IMAGE="busybox:1.37.0@sha256:9532d8c39891ca2ecde4d30d7710e01fb739c87a8b9299685c63704296b16028"

DRY_RUN=0
CONFIRMED=0
LEAVE_STOPPED=0
ARCHIVE=""
INPUT_STAGE_DIR=""

log() { printf '\033[1;34m[restore]\033[0m %s\n' "$*"; }
fail() {
	printf '\033[1;31m[restore] ERROR:\033[0m %s\n' "$*" >&2
	exit 1
}

usage() {
	printf 'Usage: %s [--dry-run | --confirm-restore] [--leave-stopped] ARCHIVE\n' "$0"
}

private_env_file_ok() {
	local owner_uid current_uid mode permission_bits
	[ -f "$ENV_FILE" ] && [ ! -L "$ENV_FILE" ] && [ -r "$ENV_FILE" ] || return 1
	owner_uid="$(stat -c '%u' -- "$ENV_FILE")" || return 1
	current_uid="$(id -u)" || return 1
	[ "$owner_uid" = "$current_uid" ] || return 1
	mode="$(stat -c '%a' -- "$ENV_FILE")" || return 1
	[[ "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
	permission_bits=$((8#$mode))
	[ $((permission_bits & 077)) -eq 0 ]
}

private_input_file_ok() {
	local path="$1" owner_uid current_uid mode permission_bits
	[ -f "$path" ] && [ ! -L "$path" ] && [ -r "$path" ] || return 1
	owner_uid="$(stat -c '%u' -- "$path")" || return 1
	current_uid="$(id -u)" || return 1
	[ "$owner_uid" = "$current_uid" ] || return 1
	mode="$(stat -c '%a' -- "$path")" || return 1
	[[ "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
	permission_bits=$((8#$mode))
	[ $((permission_bits & 077)) -eq 0 ]
}

private_directory_ok() {
	local path="$1" owner_uid current_uid mode permission_bits
	[ -d "$path" ] && [ ! -L "$path" ] || return 1
	owner_uid="$(stat -c '%u' -- "$path")" || return 1
	current_uid="$(id -u)" || return 1
	[ "$owner_uid" = "$current_uid" ] || return 1
	mode="$(stat -c '%a' -- "$path")" || return 1
	[[ "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
	permission_bits=$((8#$mode))
	[ $((permission_bits & 077)) -eq 0 ]
}

cleanup_input_stage() {
	if [ -n "$INPUT_STAGE_DIR" ] && [ -d "$INPUT_STAGE_DIR" ]; then
		rm -rf -- "$INPUT_STAGE_DIR"
	fi
	INPUT_STAGE_DIR=""
}

acquire_release_lock() {
	local inherited_fd="${COMPOSIO_PRODUCTION_LOCK_FD:-}" lock_identity fd_identity
	command -v flock >/dev/null 2>&1 || fail "flock is required for production operations."
	mkdir -p "$(dirname "$RELEASE_LOCK_PATH")"
	chmod 0700 "$(dirname "$RELEASE_LOCK_PATH")"
	touch "$RELEASE_LOCK_PATH"
	chmod 0600 "$RELEASE_LOCK_PATH"

	if [ -n "$inherited_fd" ]; then
		[ "$inherited_fd" = "$RELEASE_LOCK_FD" ] \
			|| fail "The inherited production-operation lock is invalid."
		[ -e "/proc/$$/fd/$RELEASE_LOCK_FD" ] \
			|| fail "The inherited production-operation lock descriptor is unavailable."
		lock_identity="$(stat -Lc '%d:%i' -- "$RELEASE_LOCK_PATH")" || return 1
		fd_identity="$(stat -Lc '%d:%i' -- "/proc/$$/fd/$RELEASE_LOCK_FD")" || return 1
		[ "$lock_identity" = "$fd_identity" ] \
			|| fail "The inherited production-operation lock does not match this repository."
		flock -n "$RELEASE_LOCK_FD" \
			|| fail "Another production backup, restore, or deployment is already running."
		return 0
	fi

	exec 9>"$RELEASE_LOCK_PATH"
	flock -n "$RELEASE_LOCK_FD" \
		|| fail "Another production backup, restore, or deployment is already running."
	export COMPOSIO_PRODUCTION_LOCK_FD="$RELEASE_LOCK_FD"
}

isolated_command() {
	local name
	local -a clean_environment=(
		env
		-i
		"PATH=$PATH"
	)
	if [ "${COMPOSIO_PRODUCTION_LOCK_FD:-}" = "$RELEASE_LOCK_FD" ]; then
		clean_environment+=(
			"COMPOSIO_PRODUCTION_LOCK_FD=$COMPOSIO_PRODUCTION_LOCK_FD"
		)
	fi
	for name in \
		DOCKER_HOST \
		DOCKER_CONTEXT \
		DOCKER_CONFIG \
		DOCKER_CERT_PATH \
		DOCKER_TLS_VERIFY; do
		if [[ -v "$name" ]]; then
			clean_environment+=("$name=${!name}")
		fi
	done
	"${clean_environment[@]}" "$@"
}

docker_command() {
	isolated_command docker "$@"
}

for argument in "$@"; do
	case "$argument" in
		--dry-run)
			DRY_RUN=1
			;;
		--confirm-restore)
			CONFIRMED=1
			;;
		--leave-stopped)
			LEAVE_STOPPED=1
			;;
		--help|-h)
			usage
			exit 0
			;;
		-*)
			fail "Unknown option."
			;;
		*)
			[ -z "$ARCHIVE" ] || fail "Exactly one archive must be supplied."
			ARCHIVE="$argument"
			;;
	esac
done

[ -n "$ARCHIVE" ] || fail "An archive path is required."
[ "$DRY_RUN" -eq 0 ] || [ "$CONFIRMED" -eq 0 ] \
	|| fail "--dry-run and --confirm-restore are mutually exclusive."
[ "$DRY_RUN" -eq 0 ] || [ "$LEAVE_STOPPED" -eq 0 ] \
	|| fail "--leave-stopped is valid only with --confirm-restore."
if [ "$DRY_RUN" -eq 0 ] && [ "$CONFIRMED" -ne 1 ]; then
	fail "Refusing to overwrite production volumes without --confirm-restore."
fi

command -v python3 >/dev/null 2>&1 || fail "python3 is required."
command -v cp >/dev/null 2>&1 || fail "cp is required."
command -v tar >/dev/null 2>&1 || fail "tar is required."
case "$ARCHIVE" in
	*:*|*$'\n'*) fail "Archive path contains unsupported characters." ;;
esac
ARCHIVE_DIR="$(cd "$(dirname "$ARCHIVE")" && pwd -P)"
ARCHIVE_NAME="$(basename "$ARCHIVE")"
ARCHIVE_SOURCE="$ARCHIVE_DIR/$ARCHIVE_NAME"
CHECKSUM_SOURCE="$ARCHIVE_SOURCE.sha256"
[[ "$ARCHIVE_NAME" =~ ^production-state-[0-9]{8}T[0-9]{6}Z\.tar\.gz$ ]] \
	|| fail "Archive filename does not match a production backup."
private_input_file_ok "$ARCHIVE_SOURCE" \
	|| fail "The archive must be a private regular file owned by the restore user."
private_input_file_ok "$CHECKSUM_SOURCE" \
	|| fail "The matching checksum must be a private regular file owned by the restore user."

# All later validation and extraction reads one private staged copy. This closes
# the local validation-to-extraction race: replacing or rewriting the supplied
# path after this point cannot change the bytes restored into production.
if [ -e "$INPUT_STAGE_ROOT" ] || [ -L "$INPUT_STAGE_ROOT" ]; then
	private_directory_ok "$INPUT_STAGE_ROOT" \
		|| fail "The restore input staging directory is not private."
else
	mkdir -m 0700 -- "$INPUT_STAGE_ROOT"
fi
private_directory_ok "$INPUT_STAGE_ROOT" \
	|| fail "The restore input staging directory is not private."
INPUT_STAGE_DIR="$(mktemp -d "$INPUT_STAGE_ROOT/input.XXXXXX")"
chmod 0700 "$INPUT_STAGE_DIR"
trap cleanup_input_stage EXIT INT TERM
ARCHIVE="$INPUT_STAGE_DIR/$ARCHIVE_NAME"
CHECKSUM="$ARCHIVE.sha256"
cp --reflink=auto -- "$ARCHIVE_SOURCE" "$ARCHIVE"
cp --reflink=auto -- "$CHECKSUM_SOURCE" "$CHECKSUM"
chmod 0400 "$ARCHIVE" "$CHECKSUM"

# Validate the exact adjacent checksum without asking sha256sum to follow a
# filename embedded in an untrusted checksum file.
python3 - "$ARCHIVE" "$CHECKSUM" <<'PY' \
	|| fail "Archive checksum validation failed."
import hashlib
import hmac
import os
import re
import sys

archive, checksum = sys.argv[1:]
with open(checksum, encoding="ascii") as handle:
    line = handle.read()
match = re.fullmatch(r"([0-9a-f]{64})  ([^\r\n]+)\n?", line)
if match is None or match.group(2) != os.path.basename(archive):
    raise SystemExit(1)
digest = hashlib.sha256()
with open(archive, "rb") as handle:
    for block in iter(lambda: handle.read(1024 * 1024), b""):
        digest.update(block)
if not hmac.compare_digest(digest.hexdigest(), match.group(1)):
    raise SystemExit(1)
PY

# Inspect headers only. Reject path traversal, duplicate names, links, devices,
# sparse/special entries, unexpected roots, environment files, and oversized
# archive metadata before tar is allowed to extract anything.
python3 - "$ARCHIVE" <<'PY' \
	|| fail "Archive structure validation failed."
import json
import pathlib
import re
import sys
import tarfile

archive = sys.argv[1]
allowed_roots = {"ops_data", "credential_vault", "browser_profiles", "runtime_config"}
required = {
    "ops_data/ops.db",
    "credential_vault/credentials.db",
    "runtime_config/deployed-sha.txt",
    "runtime_config/compose.prod.yaml",
    "runtime_config/deploy/Caddyfile",
}
allowed_evidence = {
    "runtime_config",
    "runtime_config/deploy",
    *required,
}
forbidden_names = {
    ".env",
    ".env.production",
    "secret_vault_key",
    "browser_storage_state_key",
    "langgraph_aes_key",
}
seen: set[str] = set()
total_size = 0
with tarfile.open(archive, mode="r:gz") as bundle:
    members = bundle.getmembers()
    if not members or len(members) > 200_000:
        raise SystemExit(1)
    for member in members:
        raw_name = member.name
        name = raw_name.rstrip("/")
        path = pathlib.PurePosixPath(name)
        if (
            not name
            or raw_name.startswith("/")
            or "\\" in raw_name
            or "\x00" in raw_name
            or any(ord(character) < 32 for character in raw_name)
            or any(part in {"", ".", ".."} for part in path.parts)
            or path.parts[0] not in allowed_roots
            or name in seen
        ):
            raise SystemExit(1)
        seen.add(name)
        if not (member.isdir() or member.isfile()):
            raise SystemExit(1)
        if path.parts[0] == "runtime_config" and name not in allowed_evidence:
            raise SystemExit(1)
        if any(part.casefold() in forbidden_names for part in path.parts):
            raise SystemExit(1)
        total_size += member.size
        if member.size > 10 * 1024**3 or total_size > 30 * 1024**3:
            raise SystemExit(1)
    if not required.issubset(seen):
        raise SystemExit(1)
    sha_member = bundle.getmember("runtime_config/deployed-sha.txt")
    sha_file = bundle.extractfile(sha_member)
    if sha_file is None:
        raise SystemExit(1)
    deployed_sha = sha_file.read(129).decode("ascii", errors="strict").strip()
    if re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", deployed_sha) is None:
        raise SystemExit(1)
    try:
        marker_member = bundle.getmember("ops_data/deploy-acceptance.json")
    except KeyError:
        marker_member = None
    if marker_member is not None:
        if marker_member.size > 512:
            raise SystemExit(1)
        marker_file = bundle.extractfile(marker_member)
        if marker_file is None:
            raise SystemExit(1)
        marker = json.loads(marker_file.read(513).decode("utf-8", errors="strict"))
        if (
            not isinstance(marker, dict)
            or set(marker)
            != {"schema_version", "revision", "acceptance_digest"}
            or marker.get("schema_version") != 1
            or marker.get("revision") != deployed_sha
            or re.fullmatch(r"[0-9a-f]{64}", marker.get("acceptance_digest", ""))
            is None
        ):
            raise SystemExit(1)
PY

# Shape alone is not recoverability. Open both databases from isolated temporary
# files, run SQLite's integrity checker, and require the application-owned core
# tables before a dry-run may report success. No row values are read or printed.
python3 - "$ARCHIVE" <<'PY' \
	|| fail "Archived database integrity validation failed."
import pathlib
import sqlite3
import sys
import tarfile
import tempfile

archive = sys.argv[1]
required_tables = {
    "ops_data/ops.db": {"runs", "audit_events"},
    "credential_vault/credentials.db": {"vault_entries"},
}
with tempfile.TemporaryDirectory(prefix="composio-restore-check-") as directory:
    root = pathlib.Path(directory)
    with tarfile.open(archive, mode="r:gz") as bundle:
        for member_name, expected_tables in required_tables.items():
            source = bundle.extractfile(member_name)
            if source is None:
                raise SystemExit(1)
            target = root / pathlib.PurePosixPath(member_name).name
            with target.open("wb") as handle:
                while block := source.read(1024 * 1024):
                    handle.write(block)
            connection = sqlite3.connect(
                f"file:{target}?mode=ro&immutable=1",
                uri=True,
            )
            try:
                integrity = connection.execute("PRAGMA quick_check").fetchall()
                if integrity != [("ok",)]:
                    raise SystemExit(1)
                tables = {
                    str(row[0])
                    for row in connection.execute(
                        "SELECT name FROM sqlite_schema WHERE type = 'table'"
                    )
                }
                if not expected_tables.issubset(tables):
                    raise SystemExit(1)
            finally:
                connection.close()
PY

find_validation_api_image() {
	local api_ids api_count api_id
	api_ids="$(
		docker_command ps --all \
			--filter "label=com.docker.compose.project=$PROJECT" \
			--filter "label=com.docker.compose.service=api" \
			--quiet
	)"
	api_count="$(
		printf '%s\n' "$api_ids" | awk 'NF { count += 1 } END { print count + 0 }'
	)"
	[ "$api_count" -eq 1 ] || return 1
	api_id="$api_ids"
	API_IMAGE_ID="$(
		docker_command inspect --format '{{.Image}}' "$api_id"
	)" || return 1
	[ -n "$API_IMAGE_ID" ] || return 1
	docker_command image inspect "$API_IMAGE_ID" >/dev/null 2>&1
}

validate_state_mounts() {
	local data_source="$1" vault_source="$2" browser_source="$3" runtime_user="$4"
	docker_command run --rm --interactive \
		--read-only \
		--network none \
		--user "$runtime_user" \
		--cap-drop ALL \
		--security-opt no-new-privileges:true \
		--tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777 \
		--env-file "$ENV_FILE" \
		-v "${data_source}:/data:ro" \
		-v "${vault_source}:/vault:ro" \
		-v "${browser_source}:/browser-data:ro" \
		"$API_IMAGE_ID" python - <<'PY'
import json
import os
import pathlib
import re
import sqlite3


def connect_readonly(path: pathlib.Path) -> sqlite3.Connection:
    connection = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
    if connection.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
        raise ValueError
    return connection


def table_names(connection: sqlite3.Connection) -> set[str]:
    return {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_schema WHERE type = 'table'"
        )
    }


def validate() -> None:
    from cryptography.fernet import Fernet

    ops = connect_readonly(pathlib.Path("/data/ops.db"))
    try:
        if not {"runs", "audit_events"}.issubset(table_names(ops)):
            raise ValueError
    finally:
        ops.close()

    vault = connect_readonly(pathlib.Path("/vault/credentials.db"))
    try:
        tables = table_names(vault)
        if "vault_entries" not in tables:
            raise ValueError
        key = os.environ.get("SECRET_VAULT_KEY", "").encode("ascii")
        cipher = Fernet(key)
        for (ciphertext,) in vault.execute("SELECT ciphertext FROM vault_entries"):
            cipher.decrypt(bytes(ciphertext))
        for table in ("staged_signup_logins", "staged_existing_logins"):
            if table not in tables:
                continue
            for email_ciphertext, password_ciphertext in vault.execute(
                f"SELECT email_ciphertext, password_ciphertext FROM {table}"
            ):
                cipher.decrypt(bytes(email_ciphertext))
                cipher.decrypt(bytes(password_ciphertext))
    finally:
        vault.close()

    checkpoint_path = pathlib.Path("/data/checkpoints.db")
    if checkpoint_path.exists():
        checkpoint = connect_readonly(checkpoint_path)
        try:
            tables = table_names(checkpoint)
            if not {"checkpoints", "writes"}.issubset(tables):
                raise ValueError
            key = os.environ.get("LANGGRAPH_AES_KEY", "").encode("utf-8")
            if len(key) not in {16, 24, 32}:
                raise ValueError
            from langgraph.checkpoint.serde.encrypted import EncryptedSerializer
            from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer

            strict = JsonPlusSerializer(
                pickle_fallback=False,
                allowed_json_modules=None,
                allowed_msgpack_modules=None,
            )
            serializer = EncryptedSerializer.from_pycryptodome_aes(
                serde=strict,
                key=key,
            )
            for value_type, value, metadata in checkpoint.execute(
                "SELECT type, checkpoint, metadata FROM checkpoints"
            ):
                serializer.loads_typed((str(value_type), bytes(value)))
                if metadata is not None:
                    parsed = json.loads(bytes(metadata))
                    if not isinstance(parsed, dict):
                        raise ValueError
            for value_type, value in checkpoint.execute(
                "SELECT type, value FROM writes"
            ):
                serializer.loads_typed((str(value_type), bytes(value)))
        finally:
            checkpoint.close()

    provider_effects_path = pathlib.Path("/data/provider_effects.db")
    if provider_effects_path.exists():
        provider_effects = connect_readonly(provider_effects_path)
        provider_effects.close()

    acceptance_path = pathlib.Path("/data/deploy-acceptance.json")
    if acceptance_path.exists():
        marker = json.loads(acceptance_path.read_text(encoding="utf-8"))
        if (
            not isinstance(marker, dict)
            or set(marker)
            != {"schema_version", "revision", "acceptance_digest"}
            or marker.get("schema_version") != 1
            or re.fullmatch(r"[0-9a-f]{40}(?:[0-9a-f]{24})?", marker.get("revision", ""))
            is None
            or re.fullmatch(r"[0-9a-f]{64}", marker.get("acceptance_digest", ""))
            is None
        ):
            raise ValueError

    state_files = tuple(
        pathlib.Path("/browser-data/storage-state").glob("*.state")
    )
    if state_files:
        browser_cipher = Fernet(
            os.environ.get("BROWSER_STORAGE_STATE_KEY", "").encode("ascii")
        )
        for path in state_files:
            envelope = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(envelope, dict):
                raise ValueError
            decrypted = browser_cipher.decrypt(
                str(envelope.get("state") or "").encode("ascii")
            )
            if not isinstance(json.loads(decrypted), dict):
                raise ValueError


try:
    validate()
except Exception:
    raise SystemExit(1) from None
PY
}

if [ "$DRY_RUN" -eq 1 ]; then
	command -v docker >/dev/null 2>&1 || fail "Docker is required for encrypted dry-run validation."
	command -v flock >/dev/null 2>&1 || fail "flock is required for production operations."
	private_env_file_ok \
		|| fail ".env.production must be a private regular file owned by the restore user."
	acquire_release_lock
	docker_command info >/dev/null 2>&1 || fail "Cannot communicate with the Docker daemon."
	find_validation_api_image \
		|| fail "Exactly one local API container image is required for encrypted validation."
	DRY_VALIDATION_DIR="$(mktemp -d "${TMPDIR:-/tmp}/composio-restore-dry-run.XXXXXX")"
	chmod 0700 "$DRY_VALIDATION_DIR"
	cleanup_dry_validation() {
		rm -rf -- "$DRY_VALIDATION_DIR"
		cleanup_input_stage
	}
	trap cleanup_dry_validation EXIT INT TERM
	# --no-same-owner is load-bearing for the dry run. The archive records the
	# in-container ops uid, and a root extraction would recreate that ownership;
	# the validation container then runs as the extracting user with --cap-drop
	# ALL, so it has no DAC_OVERRIDE and cannot read owner-only files it does not
	# own. Every production deployment runs as root, so validating a pre-deploy
	# archive failed with EACCES and looked like a key mismatch. A real restore
	# still preserves ownership: only this read-only copy follows the caller.
	tar xzf "$ARCHIVE" --no-same-owner -C "$DRY_VALIDATION_DIR" \
		ops_data credential_vault browser_profiles
	validate_state_mounts \
		"$DRY_VALIDATION_DIR/ops_data" \
		"$DRY_VALIDATION_DIR/credential_vault" \
		"$DRY_VALIDATION_DIR/browser_profiles" \
		"$(id -u):$(id -g)" \
		|| fail "Archived encrypted state does not match the current private keys."
	cleanup_dry_validation
	DRY_VALIDATION_DIR=""
	trap - EXIT INT TERM
	log "Archive, databases, encrypted state, and checksum validated; no containers or volumes were changed."
	exit 0
fi

command -v docker >/dev/null 2>&1 || fail "Docker is required for a restore."
command -v flock >/dev/null 2>&1 || fail "flock is required for production operations."
private_env_file_ok \
	|| fail ".env.production must be a private regular file owned by the restore user."
acquire_release_lock
docker_command info >/dev/null 2>&1 || fail "Cannot communicate with the Docker daemon."
docker_command image inspect "$HELPER_IMAGE" >/dev/null 2>&1 \
	|| docker_command pull "$HELPER_IMAGE" >/dev/null \
	|| fail "The immutable restore helper image is unavailable."

for volume in "$DATA_VOLUME" "$VAULT_VOLUME" "$BROWSER_VOLUME"; do
	docker_command volume inspect "$volume" >/dev/null 2>&1 \
		|| fail "A required production volume does not exist."
done

readonly -a SERVICES=(browser-worker api web caddy)
readonly -a STOP_ORDER=(caddy web api browser-worker)
declare -A CONTAINER_ID=()
declare -A ORIGINALLY_RUNNING=()
DEPLOYED_REVISION=""
for service in "${SERVICES[@]}"; do
	container_ids="$(
		docker_command ps --all \
			--filter "label=com.docker.compose.project=$PROJECT" \
			--filter "label=com.docker.compose.service=$service" \
			--quiet
	)"
	container_count="$(
		printf '%s\n' "$container_ids" | awk 'NF { count += 1 } END { print count + 0 }'
	)"
	[ "$container_count" -eq 1 ] \
		|| fail "Exactly one production container is required for every service."
	CONTAINER_ID["$service"]="$container_ids"
	running="$(
		docker_command inspect --format '{{.State.Running}}' "$container_ids"
	)" || fail "Could not inspect a production container."
	case "$running" in
		true) ORIGINALLY_RUNNING["$service"]=1 ;;
		false) ORIGINALLY_RUNNING["$service"]=0 ;;
		*) fail "A production container returned an invalid running state." ;;
	esac
	container_revision="$(
		docker_command inspect --format \
			'{{index .Config.Labels "org.opencontainers.image.revision"}}' \
			"$container_ids"
	)" || fail "Could not inspect a production revision label."
	[[ "$container_revision" =~ ^[0-9a-f]{40}([0-9a-f]{24})?$ ]] \
		|| fail "A production container has an invalid revision label."
	if [ -z "$DEPLOYED_REVISION" ]; then
		DEPLOYED_REVISION="$container_revision"
	elif [ "$container_revision" != "$DEPLOYED_REVISION" ]; then
		fail "Production containers do not share one exact revision."
	fi
done

# Reject an already-broken dependency topology before any service is stopped.
[ "${ORIGINALLY_RUNNING[caddy]}" -eq 0 ] || [ "${ORIGINALLY_RUNNING[web]}" -eq 1 ] \
	|| fail "Caddy is running while web is stopped."
[ "${ORIGINALLY_RUNNING[web]}" -eq 0 ] || [ "${ORIGINALLY_RUNNING[api]}" -eq 1 ] \
	|| fail "Web is running while API is stopped."
[ "${ORIGINALLY_RUNNING[api]}" -eq 0 ] \
	|| [ "${ORIGINALLY_RUNNING[browser-worker]}" -eq 1 ] \
	|| fail "API is running while browser-worker is stopped."

API_IMAGE_ID="$(
	docker_command inspect --format '{{.Image}}' "${CONTAINER_ID[api]}"
)" || fail "Could not identify the API image used for restore validation."
[ -n "$API_IMAGE_ID" ] || fail "The API image identity is empty."
docker_command image inspect "$API_IMAGE_ID" >/dev/null 2>&1 \
	|| fail "The API image used for restore validation is unavailable."

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
for private_output_directory in "$SAFETY_DIR" "$EVIDENCE_ROOT"; do
	if [ -e "$private_output_directory" ] || [ -L "$private_output_directory" ]; then
		private_directory_ok "$private_output_directory" \
			|| fail "Recovery output directories must be private and owned by the restore user."
	else
		mkdir -p -m 0700 -- "$private_output_directory"
	fi
done
SAFETY_DIR="$(cd "$SAFETY_DIR" && pwd -P)"
EVIDENCE_ROOT="$(cd "$EVIDENCE_ROOT" && pwd -P)"
case "$SAFETY_DIR $EVIDENCE_ROOT" in
	*:*|*$'\n'*) fail "Recovery output path contains unsupported characters." ;;
esac
chmod 0700 "$SAFETY_DIR" "$EVIDENCE_ROOT"
private_directory_ok "$SAFETY_DIR" && private_directory_ok "$EVIDENCE_ROOT" \
	|| fail "Resolved recovery output directories are not private."
SAFETY_NAME="pre-restore-${STAMP}.tar.gz"
SAFETY_ARCHIVE="$SAFETY_DIR/$SAFETY_NAME"
EVIDENCE_DIR="$EVIDENCE_ROOT/$STAMP"
SAFETY_OWNER_UID="$(id -u)"
SAFETY_OWNER_GID="$(id -g)"
[[ "$SAFETY_OWNER_UID" =~ ^[0-9]+$ ]] && [[ "$SAFETY_OWNER_GID" =~ ^[0-9]+$ ]] \
	|| fail "Could not determine the restore owner identity."
[ ! -e "$SAFETY_ARCHIVE" ] && [ ! -L "$SAFETY_ARCHIVE" ] \
	&& [ ! -e "$SAFETY_ARCHIVE.sha256" ] && [ ! -L "$SAFETY_ARCHIVE.sha256" ] \
	&& [ ! -e "$EVIDENCE_DIR" ] && [ ! -L "$EVIDENCE_DIR" ] \
	|| fail "Recovery output already exists for this timestamp; retry after the current second."
SAFETY_READY=0
MUTATION_STARTED=0
ROLLBACK_COMPLETE=0
SERVICES_STOPPED=0

restore_volumes_from_archive() {
	local source_archive="$1" source_dir source_name
	source_dir="$(cd "$(dirname "$source_archive")" && pwd -P)"
	source_name="$(basename "$source_archive")"
	docker_command run --rm \
		-e "ARCHIVE_NAME=$source_name" \
		-v "${DATA_VOLUME}:/target/ops_data" \
		-v "${VAULT_VOLUME}:/target/credential_vault" \
		-v "${BROWSER_VOLUME}:/target/browser_profiles" \
		-v "${source_dir}:/restore-source:ro" \
		"$HELPER_IMAGE" sh -eu -c '
			for target in /target/ops_data /target/credential_vault /target/browser_profiles; do
				test -d "$target"
				find "$target" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
			done
			tar xzf "/restore-source/$ARCHIVE_NAME" -C /target \
				ops_data credential_vault browser_profiles
			test -f /target/ops_data/ops.db
			test -f /target/credential_vault/credentials.db
		'
}

validate_restored_state() {
	validate_state_mounts \
		"$DATA_VOLUME" \
		"$VAULT_VOLUME" \
		"$BROWSER_VOLUME" \
		ops
}

archived_acceptance_matches_running_release() {
	tar xOf "$ARCHIVE" ops_data/deploy-acceptance.json 2>/dev/null \
		| docker_command exec --interactive "${CONTAINER_ID[api]}" \
			python -c '
import json
import sys

from ops.core.config import Settings
from ops.deploy.acceptance import deployment_payload_is_accepted

try:
    payload = json.load(sys.stdin)
    settings = Settings.from_env(dotenv_path=None)
except Exception:
    raise SystemExit(1) from None
if settings.app_revision != sys.argv[1]:
    raise SystemExit(1)
if not deployment_payload_is_accepted(settings, payload):
    raise SystemExit(1)
' "$DEPLOYED_REVISION"
}

running_release_accepts_restored_marker() {
	docker_command exec "${CONTAINER_ID[api]}" python -c '
from ops.core.config import Settings
from ops.deploy.acceptance import deployment_is_accepted

raise SystemExit(
    0 if deployment_is_accepted(Settings.from_env(dotenv_path=None)) else 1
)
'
}

stop_all_services() {
	local service
	SERVICES_STOPPED=1
	for service in "${STOP_ORDER[@]}"; do
		docker_command stop "${CONTAINER_ID[$service]}" >/dev/null || return 1
	done
}

wait_for_container_health() {
	local service="$1" timeout="$2" waited=0 status
	while :; do
		status="$(
			docker_command inspect --format \
				'{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' \
				"${CONTAINER_ID[$service]}" 2>/dev/null || printf 'unknown'
		)"
		case "$status" in
			healthy) return 0 ;;
			unhealthy|dead|exited) return 1 ;;
		esac
		[ "$waited" -lt "$timeout" ] || return 1
		sleep 3
		waited=$((waited + 3))
	done
}

start_and_validate_services() {
	local service
	for service in "${SERVICES[@]}"; do
		[ "${ORIGINALLY_RUNNING[$service]}" -eq 1 ] || continue
		docker_command start "${CONTAINER_ID[$service]}" >/dev/null || return 1
		wait_for_container_health "$service" 180 || return 1
		if [ "$service" = "api" ]; then
			running_release_accepts_restored_marker || return 1
		fi
	done
	SERVICES_STOPPED=0
}

finish_restore() {
	local status=$? service
	trap - EXIT INT TERM
	if [ "$status" -ne 0 ] && [ "$SERVICES_STOPPED" -eq 1 ]; then
		for service in "${STOP_ORDER[@]}"; do
			docker_command stop "${CONTAINER_ID[$service]}" >/dev/null 2>&1 || true
		done
	fi
	if [ "$status" -ne 0 ] \
		&& [ "$MUTATION_STARTED" -eq 1 ] \
		&& [ "$SAFETY_READY" -eq 1 ] \
		&& [ "$ROLLBACK_COMPLETE" -eq 0 ]; then
		log "Restore failed; recovering and revalidating the original volume snapshot."
		if restore_volumes_from_archive "$SAFETY_ARCHIVE" \
			&& validate_restored_state; then
			ROLLBACK_COMPLETE=1
		else
			printf '\033[1;31m[restore] FATAL:\033[0m automatic safety rollback or validation failed; all production services remain stopped.\n' >&2
			status=70
		fi
	fi
	if [ "$status" -ne 0 ] && [ "$SERVICES_STOPPED" -eq 1 ]; then
		printf '\033[1;31m[restore] ERROR:\033[0m restore was not accepted; all production services remain stopped.\n' >&2
	fi
	cleanup_input_stage
	exit "$status"
}
trap finish_restore EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [ "${ORIGINALLY_RUNNING[api]}" -eq 1 ] && [ "$LEAVE_STOPPED" -eq 0 ]; then
	archived_acceptance_matches_running_release \
		|| fail "The archive is not accepted by the exact running release; restore it with --leave-stopped, then deploy its recorded revision."
fi

log "Closing the public edge and quiescing every production service."
stop_all_services || fail "Could not stop every production service."

for volume in "$DATA_VOLUME" "$VAULT_VOLUME" "$BROWSER_VOLUME"; do
	remaining="$(docker_command ps --filter "volume=$volume" --quiet)"
	[ -z "$remaining" ] || fail "A production volume still has a running container."
done

log "Creating a timestamped safety backup of the current volumes."
docker_command run --rm \
	-e "SAFETY_NAME=$SAFETY_NAME" \
	-e "SAFETY_OWNER_UID=$SAFETY_OWNER_UID" \
	-e "SAFETY_OWNER_GID=$SAFETY_OWNER_GID" \
	-v "${DATA_VOLUME}:/source/ops_data:ro" \
	-v "${VAULT_VOLUME}:/source/credential_vault:ro" \
	-v "${BROWSER_VOLUME}:/source/browser_profiles:ro" \
	-v "${SAFETY_DIR}:/safety" \
	"$HELPER_IMAGE" sh -eu -c '
		test -f /source/ops_data/ops.db
		test -f /source/credential_vault/credentials.db
		tmp="/safety/.${SAFETY_NAME}.tmp"
		tar czf "$tmp" -C /source ops_data credential_vault browser_profiles
		tar tzf "$tmp" | grep -q "^ops_data/ops.db$"
		tar tzf "$tmp" | grep -q "^credential_vault/credentials.db$"
		tar tzf "$tmp" | grep -q "^browser_profiles/$"
		mv "$tmp" "/safety/$SAFETY_NAME"
		chmod 0600 "/safety/$SAFETY_NAME"
		cd /safety
		sha256sum "$SAFETY_NAME" > "$SAFETY_NAME.sha256"
		chmod 0600 "$SAFETY_NAME.sha256"
		chown "$SAFETY_OWNER_UID:$SAFETY_OWNER_GID" \
			"$SAFETY_NAME" "$SAFETY_NAME.sha256"
	'
[ -s "$SAFETY_ARCHIVE" ] || fail "Safety backup creation failed."
[ -s "$SAFETY_ARCHIVE.sha256" ] || fail "Safety-backup checksum creation failed."
private_input_file_ok "$SAFETY_ARCHIVE" \
	|| fail "Safety backup ownership or permissions are unsafe."
private_input_file_ok "$SAFETY_ARCHIVE.sha256" \
	|| fail "Safety-backup checksum ownership or permissions are unsafe."
SAFETY_READY=1

# Preserve only the allowlisted, non-secret deployed configuration evidence.
mkdir -p "$EVIDENCE_DIR"
chmod 0700 "$EVIDENCE_DIR"
tar xzf "$ARCHIVE" -C "$EVIDENCE_DIR" runtime_config
chmod -R go-rwx "$EVIDENCE_DIR"

log "Restoring and validating the production data volumes."
MUTATION_STARTED=1
restore_volumes_from_archive "$ARCHIVE"
validate_restored_state || fail "Restored data could not be decrypted and validated."

if [ "$LEAVE_STOPPED" -eq 0 ]; then
	log "Starting services in dependency order and requiring healthy state."
	start_and_validate_services \
		|| fail "Restored services did not pass health validation."
else
	log "Validated restore completed; all production services remain stopped as requested."
fi

MUTATION_STARTED=0
ROLLBACK_COMPLETE=1
cleanup_input_stage
trap - EXIT INT TERM
log "Restore completed. Safety backup and deployed configuration evidence were preserved."
