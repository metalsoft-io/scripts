#!/bin/bash
# vi: et st=2 sts=2 ts=2 sw=2 cindent bg=dark ft=sh
# set -x

nc="\e[00m"
bold="\e[1;37m"
gray="\e[2;37m"
lightred="\e[1;31m"
lightgreen="\e[1;32m"
yellow="\e[1;33m"
pink="\e[1;35m"
orange="\e[6;33m"
# absolute path of this script, if it runs from a file (it cd-s later; piped into bash it is not a file)
SELF="$(readlink -f "$0" 2>/dev/null)"


function debuglog ()
{
  msg="$1"
  mtype="${2:-info}"
  case "$mtype" in
    'fail') mtypeis="[\e[1;31m✗\e[0m]"; color=${3:-lightred} ;;
    'success') mtypeis="[\e[1;32m✓\e[0m]"; color=${3:-lightgreen} ;;
    *) mtypeis="${bold}[i]${nc}"; color=${3:-bold} ;;
  esac
  echo -e "${mtypeis} ${!color}${msg}${nc}"
}

# SC_SYSTEMD=1: sc-ctl.sh, its config and metalsoft-sc.service; on OVA hosts also the network hook that knows the unit.
install_sc_systemd ()
{
  local A=/opt/metalsoft/agents compose_cmd bundle_url status_url
  mkdir -p "$A/bin" "$A/last-good" "$A/run"
  chmod 0700 "$A" "$A/run"
  cat > "$A/bin/sc-ctl.sh.new" <<'MS_SC_CTL_EOF'
#!/usr/bin/env bash
# sc-ctl.sh - runs the MetalSoft site controller stack under systemd.
#
#   prestart  apply a new GC bundle, validate, pull images, fall back to last-good   (ExecStartPre)
#   run       compose up -d, remove orphans, watch for registration, wait for agent (ExecStart)
#   stop      after an agent exit: nothing more; on systemctl stop: the whole stack (ExecStop)
#   down      stop the unit and remove every container of the stack              (manual)
#   status    show config state and containers                                   (manual)
#
# The config is every file in $PREFIX except bin/ run/ staging/ last-good/ sc.conf.
# last-good/ is a copy of it, taken when the agent registered; rollbacks restore it.
#
# GC bundle: a .tar.gz holding 'manifest' and the files it lists. Manifest lines:
#   version <label>       optional, shown in logs. A bundle is identified by the sha256 of its content:
#                         the same content is applied (or rejected) once, any change is a new bundle
#   env KEY=VALUE         set KEY in .env; other lines are kept (COMPOSE_* refused)
#   env-unset KEY         remove KEY from .env
#   file <mode> <path>    copy <path> from the bundle to $PREFIX/<path>; ca/*.crt also go to the OS trust store
#   compose <path>        compose files in -f order; replaces the list when present (default: docker-compose.yaml)
#   delete <path>         remove a file or directory under $PREFIX (same path rules as 'file')
#   login <host> <base64 of user:password>   registry login, written to the engine's auth file (needs jq)
#   login-remove <host>   remove that host's registry login
#
# Requests to the GC (bundle, status) authenticate with AGENT_ID / AGENT_SECRET from .env (HTTP basic auth).
# Status: a JSON document is POSTed to GC_STATUS_URL (.env overrides sc.conf) at each step; file:// appends locally.
set -Eeuo pipefail
# .env, rendered configs and bundles contain AGENT_SECRET.
umask 077
# Hashes depend on sort order, which depends on the locale: the unit, a shell and cron must agree.
export LC_ALL=C

# The unit sets PREFIX; run by hand, the script lives in $PREFIX/bin.
PREFIX=${PREFIX:-$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)}
# shellcheck source=/dev/null
. "$PREFIX/sc.conf"
: "${ENGINE:?ENGINE not set in sc.conf}" "${PROJECT:?PROJECT not set in sc.conf}"
: "${UNIT:=metalsoft-sc}" "${AGENT_SERVICE:=ms-agent}" "${AGENT_CONTAINER:=ms-agent}"
: "${GC_BUNDLE_URL:=}" "${GC_STATUS_URL:=}" "${GC_TIMEOUT:=10}" "${CRASH_MAX:=3}"
# Pull timeouts: long for an image not on the host yet, short when a local copy can be used instead.
: "${PULL_TIMEOUT:=600}" "${PULL_TIMEOUT_LOCAL:=30}"
# After registration, the whole stack must stay running for SETTLE_SECONDS before the config counts as good.
: "${SETTLE_SECONDS:=20}"
# .env keys owned by the host, not by a config version (the OVA network hook keeps them at the current IP):
# a rollback keeps their current values instead of restoring last-good's.
: "${HOST_KEYS:=SITE_CONTROLLER_IP NFS_HOST}"
: "${GC_BUNDLE_MAX_BYTES:=52428800}" "${BUNDLE_MAX_EXTRACT_BYTES:=209715200}" "${MIN_FREE_MB:=2048}"
# Registration: the agent's marker file (README: Needed from devs), else its log line (v7.5 logs it at debug level only).
: "${HEALTH_FILE:=/tmp/ms-agent.registered}"
: "${HEALTH_PATTERN:=registration successful|agent registered with controller}" "${HEALTH_TIMEOUT:=300}" "${HEALTH_POLL:=5}"
[ "${#COMPOSE[@]}" -gt 0 ] || { echo "sc-ctl: COMPOSE not set in sc.conf" >&2; exit 1; }
[ -n "${GC_CURL_OPTS+x}" ] || GC_CURL_OPTS=()
if [ -d /usr/local/share/ca-certificates ]; then
  : "${CA_TRUST_DIR:=/usr/local/share/ca-certificates}" "${CA_UPDATE_CMD:=update-ca-certificates}"
else
  : "${CA_TRUST_DIR:=/etc/pki/ca-trust/source/anchors}" "${CA_UPDATE_CMD:=update-ca-trust}"
fi
if [ "$ENGINE" = podman ]; then
  : "${CA_ENGINE_DIR:=/etc/containers/certs.d}"; PROJECT_LABEL=io.podman.compose.project; SERVICE_FMT='{{index .Labels "com.docker.compose.service"}}'
else
  : "${CA_ENGINE_DIR:=/etc/docker/certs.d}"; PROJECT_LABEL=com.docker.compose.project; SERVICE_FMT='{{.Label "com.docker.compose.service"}}'
fi

# Reported to the GC in every status, so it only sends manifest lines this SC understands.
SC_CTL_VERSION=1
CAPABILITIES=(version env env-unset file compose delete login login-remove ca-sync status prune remove-orphans registration-marker)

LIVE=$PREFIX GOOD=$PREFIX/last-good STAGING=$PREFIX/staging RUN=$PREFIX/run
RESERVED=(bin run staging last-good last-good.tmp sc.conf)
LOGBUF=()

log() { echo "$*" >&2; LOGBUF+=("$*"); }
# Any unexpected failure (set -e) is logged with its line and reported, instead of ending the step silently.
trap 'rc=$?; trap - ERR; log "error: sc-ctl.sh line $LINENO: $BASH_COMMAND (exit $rc)"; post_status failed; exit "$rc"' ERR
die() { log "$*"; post_status failed; exit 1; }
join() { local s; s=$(printf '%s, ' "$@"); echo "${s%, }"; }
rd() { cat "$1" 2>/dev/null || true; }  # file contents, or nothing when it does not exist

env_get() {  # KEY: value from the live .env, surrounding quotes removed
  sed -n "s/^$1=//p" "$LIVE/.env" 2>/dev/null | tail -1 | sed -e "s/^'\(.*\)'\$/\1/" -e 's/^"\(.*\)"$/\1/'
}

# A bundle controls compose, .env and trusted CAs: only use a verified GC
# (CA-checked https, or -k with a pinned public key for IP / self-signed GCs).
verified_url() {
  local opts=" ${GC_CURL_OPTS[*]} "
  [[ $1 == https://* && ( $opts != *" -k "* || $opts == *" --pinnedpubkey "* ) ]] || [ "${ALLOW_INSECURE_GC:-0}" = 1 ]
}

url_host() { local h=${1#*://}; h=${h%%/*}; echo "${h##*@}"; }

# The GC host: the one serving the bundle, else GC_HOSTNAME from .env. Credentials are only ever sent there.
gc_host() { if [ -n "$GC_BUNDLE_URL" ]; then url_host "$GC_BUNDLE_URL"; else env_get GC_HOSTNAME; fi; }

# curl url [args]: with the agent's credentials when url is on the GC host (passed on stdin, not in the process list).
gc_curl() {
  local url=$1 id secret; shift
  id=$(env_get AGENT_ID) secret=$(env_get AGENT_SECRET)
  if [ -n "$id" ] && [ -n "$secret" ] && [ "$(url_host "$url")" = "$(gc_host)" ]; then
    id=${id//\\/\\\\} secret=${secret//\\/\\\\}
    printf 'user = "%s:%s"\n' "${id//\"/\\\"}" "${secret//\"/\\\"}" \
      | curl -K - -fsS --max-time "$GC_TIMEOUT" "${GC_CURL_OPTS[@]}" "$@" "$url"
  else
    curl -fsS --max-time "$GC_TIMEOUT" "${GC_CURL_OPTS[@]}" "$@" "$url"
  fi
}

# True when the GC answers at all (any HTTP status). Used to tell a GC outage from a broken config.
gc_reachable() {
  local url=${GC_BUNDLE_URL:-}
  [ -n "$url" ] || { url=$(env_get GC_HOSTNAME); [ -z "$url" ] || url=https://$url/; }
  [ -n "$url" ] || return 0
  if [[ $url == file://* ]]; then [ -e "${url#file://}" ]; return; fi
  [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "${GC_CURL_OPTS[@]}" "$url" 2>/dev/null)" != 000 ]
}

images_of() { grep -E '^[[:space:]]+image:' "$1" 2>/dev/null | awk '{print $2}' | tr -d "\"'" | sort -u; }

disk_free_mb() {
  local dir
  if [ "$ENGINE" = podman ]; then dir=$("$ENGINE" info -f '{{.Store.GraphRoot}}' 2>/dev/null); else dir=$("$ENGINE" info -f '{{.DockerRootDir}}' 2>/dev/null); fi
  df -Pm "${dir:-/}" 2>/dev/null | awk 'NR == 2 { print $4 }'
}

# Sends the state and this step's log lines to the GC. Never fails or delays the caller beyond GC_TIMEOUT:
# called as 'cmd || ...', so set -e and the ERR trap are off inside and any failure only skips the report.
post_status() { _post_status "$@" || echo "status: not sent (event $1)" >&2; LOGBUF=(); }
_post_status() {  # event
  local url body
  url=$(env_get GC_STATUS_URL); url=${url:-$GC_STATUS_URL}
  [ -n "$url" ] || return 0
  command -v jq >/dev/null || { echo "status: jq missing, not sent" >&2; return 0; }
  body=$(jq -cn --arg event "$1" --arg time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg agent "$(env_get AGENT_ID)" \
    --arg config "$(config_hash "$LIVE" 2>/dev/null)" --arg last_good "$(rd "$RUN/good.hash")" \
    --arg bundle "$(rd "$RUN/gc-bundle.hash")" --arg failures "$(rd "$RUN/failures")" \
    --arg disk_free_mb "$(disk_free_mb)" --arg agent_version "${AGENT_VERSION:-}" \
    --arg sc_ctl_version "$SC_CTL_VERSION" --arg capabilities "${CAPABILITIES[*]}" \
    --arg engine "$ENGINE $("$ENGINE" version --format '{{.Server.Version}}' 2>/dev/null || "$ENGINE" --version 2>/dev/null | awk '{print $NF}')" \
    --arg compose "$("${COMPOSE[@]}" version 2>/dev/null | head -1)" \
    --arg images "$(images_of "$RUN/resolved.yaml")" --arg messages "$(printf '%s\n' "${LOGBUF[@]+"${LOGBUF[@]}"}")" \
    '{event: $event, time: $time, agent_id: $agent, config: $config, last_good: $last_good, bundle: $bundle,
      failures: $failures, disk_free_mb: $disk_free_mb, agent_version: $agent_version,
      sc_ctl_version: $sc_ctl_version, capabilities: ($capabilities | split(" ")), engine: $engine, compose: $compose,
      images: ($images | split("\n") | map(select(length > 0))), messages: ($messages | split("\n") | map(select(length > 0)))}')
  [ -n "$body" ] || return 1
  if [[ $url == file://* ]]; then echo "$body" 2>/dev/null >>"${url#file://}"; return; fi
  verified_url "$url" || { echo "status: refused, GC_STATUS_URL is not verified https" >&2; return 0; }
  gc_curl "$url" -X POST -H 'Content-Type: application/json' --data-binary "$body" -o /dev/null 2>/dev/null \
    || echo "status: POST to GC failed" >&2
}

copy_config() {  # src dst: dst gets src's config files; files only in dst stay
  local excl=() r
  for r in "${RESERVED[@]}"; do excl+=(--exclude="./$r"); done
  tar -C "$1" "${excl[@]}" -cf - . | tar -C "$2" -xpf -
}

config_sums() {  # dir: "sha256  ./path" for each config file, sorted
  local prune=() r
  for r in "${RESERVED[@]}"; do prune+=(-path "./$r" -o); done
  (cd "$1" && find . \( "${prune[@]}" -false \) -prune -o -type f -print0 | sort -z | xargs -0 -r sha256sum)
}

config_hash() { config_sums "$1" | sha256sum | cut -c1-64; }

have_good() { [ -s "$RUN/good.hash" ] && [ -d "$GOOD" ]; }

restore_good() {  # reason
  have_good || die "$1; no last-good config to fall back to"
  local k v kept=()
  for k in $HOST_KEYS; do v=$(env_get "$k"); [ -z "$v" ] || kept+=("$k=$(sed -n "s/^$k=//p" "$LIVE/.env" | tail -1)"); done
  copy_config "$GOOD" "$LIVE"  # ponytail: files added after last-good stay; a 'delete' line removes them
  for v in "${kept[@]}"; do env_set "$LIVE/.env" "${v%%=*}" "${v#*=}"; done
  ca_sync
  log "rollback ($1): restored last-good config $(cut -c1-12 "$RUN/good.hash")"
}

compose_in() {  # dir args...: compose with the dir's compose files
  local dir=$1 files=() f; shift
  while read -r f; do files+=(-f "$f"); done < <(cat "$dir/compose-files" 2>/dev/null || echo docker-compose.yaml)
  (cd "$dir" && "${COMPOSE[@]}" -p "$PROJECT" "${files[@]}" "$@")
}

validate() {  # dir: renders the config into $RUN/resolved.yaml
  if ! compose_in "$1" config >"$RUN/resolved.yaml" 2>"$RUN/validate.err"; then
    log "invalid compose config in ${1#"$PREFIX"/}: $(head -c 400 "$RUN/validate.err" | tr '\n' ' ')"; return 1
  fi
  grep -qE "^  ${AGENT_SERVICE}:" "$RUN/resolved.yaml" || { log "config in $1 has no '$AGENT_SERVICE' service"; return 1; }
}

# Removes images of the stack's repositories that neither the live nor the last-good config uses,
# then dangling layers. Other images on the host are not touched.
prune_images() {
  local keep repos ref removed=()
  keep=$({ images_of "$RUN/resolved.yaml"; rd "$RUN/good-images"; } | sort -u)
  [ -n "$keep" ] || return 0
  repos=$(sed 's/:[^:/]*$//' <<<"$keep" | sort -u)
  while read -r ref; do
    if [[ $ref == *"<none>"* ]] || ! grep -qxF -- "${ref%:*}" <<<"$repos" || grep -qxF -- "$ref" <<<"$keep"; then continue; fi
    "$ENGINE" rmi "$ref" >/dev/null 2>&1 && removed+=("${ref##*/}")
  done < <("$ENGINE" images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null)
  "$ENGINE" image prune -f >/dev/null 2>&1 || true
  (( ${#removed[@]} == 0 )) || log "prune: removed $(join "${removed[@]}")"
}

# A failed pull is fine when the image is already on the host; fails only when one is missing.
pull_all() {
  local img rc=0 out=() free
  free=$(disk_free_mb)
  if [ -n "$free" ] && (( free < MIN_FREE_MB )); then
    log "disk: ${free} MB free (< ${MIN_FREE_MB}); pruning old images"
    prune_images
    free=$(disk_free_mb); (( ${free:-0} >= MIN_FREE_MB )) || log "disk: still ${free} MB free; pulls may fail"
  fi
  local local_copy t
  for img in $(images_of "$RUN/resolved.yaml"); do
    local_copy=0; "$ENGINE" image inspect "$img" >/dev/null 2>&1 && local_copy=1
    t=$PULL_TIMEOUT; (( ! local_copy )) || t=$PULL_TIMEOUT_LOCAL
    if timeout "$t" "$ENGINE" pull -q "$img" >/dev/null 2>&1; then out+=("${img##*/} ok")
    elif (( local_copy )); then out+=("${img##*/} FAILED, using local copy")
    else out+=("${img##*/} FAILED, not on host"); rc=1
    fi
  done
  log "pull: $(join "${out[@]}")"
  return "$rc"
}

# Mirrors $PREFIX/ca/*.crt into the OS trust store as metalsoft-<name>.crt (adds, updates, removes)
# and writes the engine's registry CA for REG_HOST.
ca_sync() {
  local c changed=0 reg certs=()
  for c in "$LIVE"/ca/*.crt; do
    [ -f "$c" ] || continue
    certs+=("$c")
    cmp -s "$c" "$CA_TRUST_DIR/metalsoft-${c##*/}" || { install -m 0644 "$c" "$CA_TRUST_DIR/metalsoft-${c##*/}"; changed=1; }
  done
  for c in "$CA_TRUST_DIR"/metalsoft-*.crt; do
    [ ! -f "$c" ] || [ -f "$LIVE/ca/${c##*/metalsoft-}" ] || { rm -f "$c"; changed=1; }
  done
  (( ! changed )) || { "$CA_UPDATE_CMD" >/dev/null 2>&1; log "ca: updated $CA_TRUST_DIR"; }
  # Registry CA for the current REG_HOST. The file written is remembered in run/engine-ca, so it can be removed
  # when no CA is left or REG_HOST changes (files placed there by someone else are never touched).
  reg=$(env_get REG_HOST)
  local want="" had
  had=$(cat "$RUN/engine-ca" 2>/dev/null || true)
  [ -z "$reg" ] || (( ${#certs[@]} == 0 )) || want=$CA_ENGINE_DIR/$reg/ca.crt
  if [ -n "$had" ] && [ "$had" != "$want" ] && [ -f "$had" ]; then rm -f "$had"; log "ca: removed $had"; fi
  if [ -z "$want" ]; then rm -f "$RUN/engine-ca"; return 0; fi
  if (( changed )) || [ ! -f "$want" ] || [ "$had" != "$want" ]; then
    mkdir -p "${want%/*}"
    cat "${certs[@]}" >"$want" && chmod 0644 "$want"
    log "ca: wrote $want"
  fi
  echo "$want" >"$RUN/engine-ca"
}

# Adds or replaces the registry login for host in the engine's auth file (as deploy-agents.sh writes REGISTRY_LOGIN).
registry_login() {  # host [base64(user:password)]: set the login, or remove it when no auth is given
  # shellcheck disable=SC2016  # $h and $a are jq variables
  local f filter='.auths[$h].auth = $a'
  if [ "$ENGINE" = podman ]; then f=${REGISTRY_AUTH_FILE:-/etc/containers/auth.json}; else f=${DOCKER_CONFIG:-${HOME:-/root}/.docker}/config.json; fi
  # shellcheck disable=SC2016
  [ -n "${2:-}" ] || { [ -s "$f" ] || return 0; filter='del(.auths[$h])'; }
  mkdir -p "$(dirname "$f")"
  [ -s "$f" ] || echo '{}' >"$f"
  jq --arg h "$1" --arg a "${2:-}" "$filter" "$f" >"$f.tmp" && mv -f "$f.tmp" "$f" && chmod 0600 "$f"
}

env_set() {  # file key [value]: replace KEY=... or append it; without a value, remove KEY. Other lines unchanged.
  local file=$1 key=$2 line found=0
  {
    if [ -f "$file" ]; then
      while IFS= read -r line || [ -n "$line" ]; do
        if [[ $line == "$key="* ]]; then (( found )) || [ $# -lt 3 ] || printf '%s=%s\n' "$key" "$3"; found=1
        else printf '%s\n' "$line"; fi
      done <"$file"
    fi
    (( found )) || [ $# -lt 3 ] || printf '%s=%s\n' "$key" "$3"
  } >"$file.tmp" && mv -f "$file.tmp" "$file"
}

safe_path() {  # relative, no '..', not reserved, not .env or compose-files
  local p=$1 r
  [[ $p =~ ^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$ && /$p/ != */../* && $p != .env && $p != compose-files ]] || return 1
  for r in "${RESERVED[@]}"; do [[ $p != "$r" && $p != "$r"/* ]] || return 1; done
}

apply_bundle() {
  [ -n "$GC_BUNDLE_URL" ] || return 0
  verified_url "$GC_BUNDLE_URL" || { log "bundle: refused, GC_BUNDLE_URL is not verified https (ALLOW_INSECURE_GC=1 for test stubs only)"; return 0; }
  rm -rf "$STAGING" && mkdir -p "$STAGING/b" "$STAGING/new"
  local err listing
  case $(env_get AGENT_SECRET) in
    ''|default) log "auth: AGENT_SECRET is empty or the shared 'default'; the GC cannot tell this SC from others" ;;
  esac
  if ! err=$(gc_curl "$GC_BUNDLE_URL" --max-filesize "$GC_BUNDLE_MAX_BYTES" -o "$STAGING/bundle.tgz" 2>&1); then
    log "bundle: GC unreachable or bundle too large (> $GC_BUNDLE_MAX_BYTES bytes), keeping current config: curl ${err#curl: }"; return 0
  fi
  listing=$(tar -tvzf "$STAGING/bundle.tgz" 2>/dev/null) || { log "bundle: rejected, not a tar.gz"; return 0; }
  # Only plain files and directories: a symlink in the bundle could point anywhere on the host.
  if grep -qv '^[-d]' <<<"$listing"; then log "bundle: rejected, contains links or special files"; return 0; fi
  if (( $(awk '{ s += $3 } END { print s + 0 }' <<<"$listing") > BUNDLE_MAX_EXTRACT_BYTES )); then
    log "bundle: rejected, unpacks to more than $BUNDLE_MAX_EXTRACT_BYTES bytes"; return 0
  fi
  # GNU tar strips a leading '/' and refuses members containing '..' (then exits non-zero).
  if ! err=$(tar -C "$STAGING/b" --no-same-owner --no-same-permissions -xzf "$STAGING/bundle.tgz" 2>&1); then
    log "bundle: rejected, cannot be unpacked: $(grep -v '^tar: Removing leading' <<<"$err" | head -2 | tr '\n' ' ')"; return 0
  fi
  [ -f "$STAGING/b/manifest" ] || { log "bundle: rejected, no manifest"; return 0; }
  # Identity = hash of the extracted files (the .tgz bytes change on every tar run even for the same files).
  local id label
  id=$( (cd "$STAGING/b" && find . -type f -print0 | sort -z | xargs -0 sha256sum) | sha256sum | cut -c1-64)
  [ "$id" != "$(rd "$RUN/gc-bundle.hash")" ] || { log "bundle: unchanged (${id:0:12})"; return 0; }
  echo "$id" >"$RUN/gc-bundle.hash"  # applied or rejected: not retried until the GC serves different content
  label=$(sed -n 's/^version //p' "$STAGING/b/manifest" | head -1 | tr -cd 'A-Za-z0-9._+-')
  local version="${label:+$label }${id:0:12}"

  copy_config "$LIVE" "$STAGING/new"
  local line kind rest mode path src cfiles=() changes=() deletes=() d logins=() lhost lauth ekey eval_
  while IFS= read -r line || [ -n "$line" ]; do
    kind=${line%% *} rest=${line#* }
    case $kind in
      ''|'#'*|version) ;;
      env)
        [[ $rest =~ ^([A-Za-z_][A-Za-z0-9_]*)=(.*)$ && ${BASH_REMATCH[1]} != COMPOSE_* ]] \
          || { log "bundle $version: rejected, bad env line"; return 0; }
        ekey=${BASH_REMATCH[1]} eval_=${BASH_REMATCH[2]}  # copied: the next =~ overwrites BASH_REMATCH
        env_set "$STAGING/new/.env" "$ekey" "$eval_"
        if [[ $ekey =~ SECRET|PASS|TOKEN|KEY ]]; then changes+=("$ekey=***"); else changes+=("$rest"); fi ;;
      env-unset)
        [[ $rest =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || { log "bundle $version: rejected, bad env-unset line '$line'"; return 0; }
        env_set "$STAGING/new/.env" "$rest"
        changes+=("unset $rest") ;;
      file)
        read -r mode path <<<"$rest"
        # No '..' (safe_path) and no links (rejected before extraction), so src stays inside the bundle.
        src=$STAGING/b/$path
        if ! [[ $mode =~ ^0[0-7]{3}$ ]] || ! safe_path "$path" || [ ! -f "$src" ] || [ -L "$src" ]; then
          log "bundle $version: rejected, bad file line '$line'"; return 0
        fi
        mkdir -p "$STAGING/new/$(dirname "$path")"
        install -m "$mode" "$src" "$STAGING/new/$path"
        changes+=("$path") ;;
      delete)
        safe_path "$rest" || { log "bundle $version: rejected, bad delete line '$line'"; return 0; }
        rm -rf "${STAGING:?}/new/$rest"
        deletes+=("$rest"); changes+=("deleted $rest") ;;
      login)
        read -r lhost lauth <<<"$rest"
        if ! [[ $lhost =~ ^[A-Za-z0-9.-]+(:[0-9]+)?$ && $lauth =~ ^[A-Za-z0-9+/]+=*$ ]] \
          || ! base64 -d <<<"$lauth" 2>/dev/null | grep -q : || ! command -v jq >/dev/null; then
          log "bundle $version: rejected, bad login line for '${lhost:-}' (or jq missing)"; return 0
        fi
        logins+=("$lhost $lauth"); changes+=("login $lhost") ;;
      login-remove)
        if ! [[ $rest =~ ^[A-Za-z0-9.-]+(:[0-9]+)?$ ]] || ! command -v jq >/dev/null; then
          log "bundle $version: rejected, bad login-remove line '$line' (or jq missing)"; return 0
        fi
        logins+=("$rest "); changes+=("login removed $rest") ;;
      compose)
        safe_path "$rest" || { log "bundle $version: rejected, bad compose line '$line'"; return 0; }
        cfiles+=("$rest") ;;
      *) log "bundle $version: rejected, unknown line '$line'"; return 0 ;;
    esac
  done <"$STAGING/b/manifest"
  if (( ${#cfiles[@]} )); then printf '%s\n' "${cfiles[@]}" >"$STAGING/new/compose-files"; changes+=("compose: ${cfiles[*]}"); fi

  validate "$STAGING/new" || { log "bundle $version: rejected"; return 0; }
  copy_config "$STAGING/new" "$LIVE"
  # copy_config only adds and overwrites; a path a later 'file' line re-created is kept.
  for d in "${deletes[@]}"; do [ -e "$STAGING/new/$d" ] || rm -rf "${LIVE:?}/$d"; done
  for d in "${logins[@]}"; do registry_login "${d%% *}" "${d#* }"; done
  ca_sync
  log "bundle $version: applied $(join "${changes[@]}")"
}

# Counts starts that ended before the agent registered. After CRASH_MAX in a row on a config
# other than last-good, last-good is restored.
account_previous_run() {
  local last prev n=0 gc_down=0
  # The flag belongs to the previous start only: read it and clear it, whatever the outcome.
  [ ! -f "$RUN/gc-unreachable" ] || gc_down=1
  rm -f "$RUN/gc-unreachable"
  last=$(rd "$RUN/last-started") || return 0
  if [ "$last" = "$(rd "$RUN/healthy")" ]; then echo "$last 0" >"$RUN/failures"; return 0; fi
  if (( gc_down )); then
    log "previous start of config ${last:0:12} did not register while the GC was unreachable; not counted"; return 0
  fi
  [ ! -f "$RUN/failures" ] || read -r prev n <"$RUN/failures" || true
  [ "${prev:-}" = "$last" ] || n=0
  n=$(( ${n:-0} + 1 )); echo "$last $n" >"$RUN/failures"
  log "previous start of config ${last:0:12} did not register ($n/$CRASH_MAX)"
  if (( n >= CRASH_MAX )) && have_good && [ "$last" = "$(config_hash "$LIVE")" ] && [ "$last" != "$(cat "$RUN/good.hash")" ]; then
    restore_good "config ${last:0:12} failed $n starts"
  fi
}

promote() {
  local hash=$1
  if [ "$(config_hash "$LIVE")" != "$hash" ]; then
    # Registered, but on files that have changed since (e.g. edited by hand): not a failure, not last-good either.
    echo "$hash" >"$RUN/healthy"
    log "config changed since start ($(diff "$RUN/last-started.sums" <(config_sums "$LIVE") 2>/dev/null \
      | awk '/^[<>]/ { print $3 }' | sort -u | paste -sd' ' -)); not saving it as last-good"
    return 1
  fi
  rm -rf "$GOOD.tmp" && mkdir -p "$GOOD.tmp"
  copy_config "$LIVE" "$GOOD.tmp"
  rm -rf "$GOOD" && mv "$GOOD.tmp" "$GOOD"
  images_of "$RUN/resolved.yaml" >"$RUN/good-images"
  echo "$hash" >"$RUN/good.hash"
  echo "$hash" >"$RUN/healthy"
}

# True when the agent's marker file was written after the given time: "<unix seconds> <agent version>".
# Read with 'cp' so the image needs no shell; the marker lives in the container, so a recreate clears it.
registered_since() {  # epoch
  local line
  line=$("$ENGINE" cp "$AGENT_CONTAINER:$HEALTH_FILE" - 2>/dev/null | tar -xOf - 2>/dev/null | head -1) || return 1
  [[ ${line%% *} =~ ^[0-9]+$ ]] && (( ${line%% *} >= $1 )) || return 1
  AGENT_VERSION=${line#* }; [ "$AGENT_VERSION" != "$line" ] || AGENT_VERSION=
}

# "service state restart-count" for each container of the project.
stack_state() {
  "$ENGINE" ps -aq --filter "label=$PROJECT_LABEL=$PROJECT" 2>/dev/null \
    | xargs -r "$ENGINE" inspect -f '{{index .Config.Labels "com.docker.compose.service"}} {{.State.Status}} {{.RestartCount}}' 2>/dev/null | sort
}

# True when every service of the config has a running container that did not restart during SETTLE_SECONDS.
stack_settled() {
  local before after svcs s bad=()
  before=$(stack_state); sleep "$SETTLE_SECONDS"; after=$(stack_state)
  svcs=$(awk '/^services:/ { f = 1; next } /^[^ ]/ { f = 0 } f && /^  [^ ]/ { sub(/^  /, ""); sub(/:.*/, ""); print }' "$RUN/resolved.yaml")
  for s in $svcs; do
    if ! grep -q "^$s running " <<<"$after"; then bad+=("$s $(awk -v s="$s" '$1 == s { print $2 }' <<<"$after" | head -1)")
    elif [ "$(grep "^$s " <<<"$before")" != "$(grep "^$s " <<<"$after")" ]; then bad+=("$s restarted")
    fi
  done
  (( ${#bad[@]} == 0 )) || { log "stack: not healthy after ${SETTLE_SECONDS}s: $(join "${bad[@]}")"; return 1; }
}

# A start that did not end healthy: report it, and restart unless that would not help.
unhealthy() {  # hash reason
  if [ "$1" = "$(rd "$RUN/good.hash")" ]; then
    log "$2 on the last-good config; nothing to roll back to, leaving it running"
  elif ! gc_reachable; then
    touch "$RUN/gc-unreachable"
    log "$2 while the GC is unreachable; not counted as a failure of config ${1:0:12}"
  else
    log "$2; restarting to count a failure of config ${1:0:12}"
    post_status unhealthy
    "$ENGINE" stop -t 30 "$AGENT_CONTAINER" >/dev/null 2>&1 || true
    return
  fi
  post_status unhealthy
}

watch_health() {
  local since=$1 epoch=$2 hash=$3 waited=0 how=
  LOGBUF=()
  while (( waited < HEALTH_TIMEOUT )); do
    if registered_since "$epoch"; then how=marker
    elif "$ENGINE" logs --since "$since" "$AGENT_CONTAINER" 2>&1 | grep -qE -- "$HEALTH_PATTERN"; then how="log line"
    fi
    [ -z "$how" ] || break
    sleep "$HEALTH_POLL"; waited=$(( waited + HEALTH_POLL ))
  done
  [ -n "$how" ] || { unhealthy "$hash" "agent did not register within ${HEALTH_TIMEOUT}s"; return 0; }
  log "agent registered after ${waited}s (${how}${AGENT_VERSION:+, $AGENT_VERSION})"
  stack_settled || { unhealthy "$hash" "stack not healthy"; return 0; }
  if promote "$hash"; then
    log "stack running; config ${hash:0:12} is last-good"
    prune_images
  fi
  post_status registered
}

# Removes containers of this compose project whose service is no longer in the config.
# (docker compose has --remove-orphans; podman-compose accepts it on 'up' but ignores it.)
remove_orphans() {
  local svcs c s
  svcs=$(awk '/^services:/ { f = 1; next } /^[^ ]/ { f = 0 } f && /^  [^ ]/ { sub(/^  /, ""); sub(/:.*/, ""); print }' "$RUN/resolved.yaml")
  [ -n "$svcs" ] || return 0
  while read -r c s; do
    if [ -z "$c" ] || grep -qxF -- "$s" <<<"$svcs"; then continue; fi
    "$ENGINE" rm -f "$c" >/dev/null 2>&1 && log "orphan: removed $c (service '$s' is no longer in the config)"
  done < <("$ENGINE" ps -a --filter "label=$PROJECT_LABEL=$PROJECT" --format "{{.Names}} $SERVICE_FMT" 2>/dev/null)
}

cmd_prestart() {
  mkdir -p "$RUN"
  exec 9>"$RUN/lock"; flock -w 600 9 || die "another sc-ctl run holds $RUN/lock"
  account_previous_run
  apply_bundle
  if ! validate "$LIVE"; then
    restore_good "live config invalid"
    validate "$LIVE" || die "last-good config is invalid too"
  fi
  if ! pull_all; then
    if ! have_good || [ "$(config_hash "$LIVE")" = "$(cat "$RUN/good.hash")" ]; then
      die "images missing and nothing to fall back to; retrying"
    fi
    restore_good "images missing"
    { validate "$LIVE" && pull_all; } || die "cannot start the last-good config either; retrying"
  fi
  local h; h=$(config_hash "$LIVE"); echo "$h" >"$RUN/last-started"; config_sums "$LIVE" >"$RUN/last-started.sums"
  rm -f "$RUN/healthy"
  log "start: config ${h:0:12}$([ "$h" != "$(rd "$RUN/good.hash")" ] || echo ' (last-good)')"
  post_status starting
}

cmd_run() {
  local since epoch out code
  since=$(date -u +%Y-%m-%dT%H:%M:%SZ) epoch=$(date +%s)
  out=$(compose_in "$LIVE" up -d 2>&1) || die "up failed: $out"
  # docker compose prints "Container <name> <state>" per step; keep the last state of each.
  out=$(awk '$1 == "Container" { s[$2] = tolower($3) } END { for (c in s) printf "%s %s, ", c, s[c] }' <<<"$out" | sed 's/, $//')
  # podman-compose prints no per-container states; list the project's containers instead.
  [ -n "$out" ] || out=$("$ENGINE" ps -a --filter "label=$PROJECT_LABEL=$PROJECT" --format '{{.Names}} {{.State}}' 2>/dev/null | paste -sd, - | sed 's/,/, /g')
  log "up: ${out:-done}"
  remove_orphans
  watch_health "$since" "$epoch" "$(cat "$RUN/last-started")" &
  code=$("$ENGINE" wait "$AGENT_CONTAINER") || die "cannot wait for $AGENT_CONTAINER"
  log "agent exited${code:+ (code $code$([ "$code" != 75 ] || echo ', upgrade requested'))}"
  if [ "$(rd "$RUN/healthy")" != "$(cat "$RUN/last-started")" ] && ! gc_reachable; then
    touch "$RUN/gc-unreachable"; log "agent exited before registering while the GC is unreachable; not counted as a failure"
  fi
  post_status exited
}

# ExecStop. systemd sets EXIT_CODE only when the main process (the agent) already exited: then nothing to do,
# the agent restarts alone and the sidecars keep running. Without it, this is 'systemctl stop/restart': stop the stack.
cmd_stop() {
  if [ -n "${EXIT_CODE:-}" ]; then
    "$ENGINE" stop -t 30 "$AGENT_CONTAINER" >/dev/null 2>&1 || true
  else
    compose_in "$LIVE" stop >/dev/null 2>&1 || true
    log "stack stopped (systemctl stop/restart)"
  fi
}

cmd_status() {
  echo "unit:          /etc/systemd/system/$UNIT.service"
  echo "live config:   $(config_hash "$LIVE" | cut -c1-12)"
  echo "last-good:     $(cut -c1-12 "$RUN/good.hash" 2>/dev/null || echo none)"
  echo "registered:    $(cut -c1-12 "$RUN/healthy" 2>/dev/null || echo no)"
  echo "failures:      $(awk '{print substr($1,1,12), $2}' "$RUN/failures" 2>/dev/null || echo none)"
  echo "GC bundle:     $(cut -c1-12 "$RUN/gc-bundle.hash" 2>/dev/null || echo none)"
  echo "compose files: $(xargs <"$LIVE/compose-files" 2>/dev/null || echo docker-compose.yaml)"
  echo "disk free:     $(disk_free_mb) MB"
  "$ENGINE" ps -a --format '{{.Names}}  {{.Image}}  {{.Status}}'
}

case ${1:-} in
  prestart) cmd_prestart ;;
  run)      cmd_run ;;
  stop)     cmd_stop ;;
  down)     systemctl stop "$UNIT" || true; compose_in "$LIVE" down ;;
  status)   cmd_status ;;
  *) echo "usage: $0 prestart|run|stop|down|status" >&2; exit 2 ;;
esac
MS_SC_CTL_EOF
  chmod 0755 "$A/bin/sc-ctl.sh.new" && mv -f "$A/bin/sc-ctl.sh.new" "$A/bin/sc-ctl.sh"

  # GC endpoints: from SC_BUNDLE_URL / SC_STATUS_URL, else kept from the previous install
  bundle_url="${SC_BUNDLE_URL-$( . "$A/sc.conf" 2>/dev/null; echo "${GC_BUNDLE_URL:-}")}"
  status_url="${SC_STATUS_URL-$( . "$A/sc.conf" 2>/dev/null; echo "${GC_STATUS_URL:-}")}"
  if [ "$DOCKERBIN" == "docker" ]; then compose_cmd="docker compose"; else compose_cmd="/usr/local/bin/podman-compose"; fi
  (
    umask 077
    {
      echo "# Written by deploy-agents.sh (SC_SYSTEMD=1); read by sc-ctl.sh."
      printf 'ENGINE=%q\nCOMPOSE=(%s)\nPROJECT=agents\nUNIT=metalsoft-sc\nAGENT_SERVICE=ms-agent\nAGENT_CONTAINER=ms-agent\n' "$DOCKERBIN" "$compose_cmd"
      printf 'GC_BUNDLE_URL=%q\nGC_STATUS_URL=%q\nGC_CURL_OPTS=()\n' "$bundle_url" "$status_url"
    } > "$A/sc.conf.new" && mv -f "$A/sc.conf.new" "$A/sc.conf"
  )

  local after="network-online.target" requires=""
  if [ "$DOCKERBIN" == "docker" ]; then after="$after docker.service"; requires="Requires=docker.service"; fi
  cat > /etc/systemd/system/metalsoft-sc.service <<EOF
# Written by deploy-agents.sh (SC_SYSTEMD=1)
[Unit]
Description=MetalSoft site controller stack
Wants=network-online.target
After=$after
$requires
# Only one manager for the stack
Conflicts=podman-compose-agents.service
# Never give up restarting (default: stop after 5 starts in 10 s)
StartLimitIntervalSec=0

[Service]
Type=simple
WorkingDirectory=$A
Environment=PREFIX=$A
Environment=HOME=/root
# proxy settings (http_proxy, no_proxy) as ms-sc-set-gc-ip writes them, for sc-ctl.sh's requests to the GC
EnvironmentFile=-/etc/environment
SyslogIdentifier=metalsoft-sc
# Fetch the GC bundle, validate, pull images, fall back to last-good
ExecStartPre=$A/bin/sc-ctl.sh prestart
# compose up -d, then wait for the ms-agent container
ExecStart=$A/bin/sc-ctl.sh run
# After an agent exit only the agent restarts; on systemctl stop/restart the whole stack stops
ExecStop=$A/bin/sc-ctl.sh stop
Restart=always
RestartSec=5
TimeoutStartSec=3600
TimeoutStopSec=60

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload

  # OVA login banner: it reads DATACENTER_ID from compose, which now holds ${DATACENTER_ID}; patch the one line
  # in place (the script differs between OVA versions) so it falls back to .env
  local banner=/etc/ms-pre-login-ips n rest
  if [ -f "$banner" ] && ! grep -q 'agents/.env' "$banner"; then
    n="$(grep -n '^dcname=.*DATACENTER_ID.*" && if grep -q' "$banner" | head -1 | cut -d: -f1)"
    if [ -n "$n" ]; then
      rest="$(sed -n "${n}p" "$banner" | sed 's/^dcname=.*" && \(if grep -q .*\)$/\1/')"
      {
        head -n $((n-1)) "$banner"
        sed -n "${n}p" "$banner" | sed 's/" && if grep -q .*$/"/'
        cat <<'MS_SC_BANNER_EOF'
# compose run by metalsoft-sc.service references ${DATACENTER_ID}: the value is in .env
case "$dcname" in '${'*|'') dcname="$(grep -Po "^DATACENTER_ID='?\K[^']*" /opt/metalsoft/agents/.env 2>/dev/null|tail -1)" ;; esac
MS_SC_BANNER_EOF
        printf 'test -n "$dcname" && %s\n' "$rest"
        tail -n +$((n+1)) "$banner"
      } > "$banner.new" && bash -n "$banner.new" && chmod 0755 "$banner.new" && mv -f "$banner.new" "$banner" \
        && debuglog "Patched $banner to read DATACENTER_ID from .env"
      rm -f "$banner.new"
    fi
  fi

  # An older local copy (the OVA keeps one in /root) would rebuild the plain-compose stack behind the unit's back:
  # replace it with this script when it runs from a file, else with a stub that points to the one-liner.
  if [ -f /root/deploy-agents.sh ] && ! grep -q 'SC_SYSTEMD' /root/deploy-agents.sh; then
    cp -p /root/deploy-agents.sh /root/deploy-agents.sh.pre-systemd
    if [ -f "$SELF" ] && grep -q 'SC_SYSTEMD' "$SELF"; then
      cp -f "$SELF" /root/deploy-agents.sh && debuglog "Replaced the old /root/deploy-agents.sh with this version"
    else
      cat > /root/deploy-agents.sh <<'MS_SC_STUB_EOF'
#!/bin/bash
echo "This site controller runs under metalsoft-sc.service; the old deploy-agents.sh kept here would bypass it." >&2
echo "Run the one-liner from the Global Controller (it fetches the current deploy-agents.sh). Old copy: /root/deploy-agents.sh.pre-systemd" >&2
exit 1
MS_SC_STUB_EOF
      debuglog "Replaced the old /root/deploy-agents.sh with a stub (the old copy would bypass metalsoft-sc.service)"
    fi
  fi

  # OVA: the dcrestart alias restarts the unit instead of compose; the banner drops the drop-folder note
  if grep -q '^alias dcrestart=' /root/.bashrc 2>/dev/null && ! grep -q '^alias dcrestart=.*metalsoft-sc' /root/.bashrc; then
    { grep -v '^alias dcrestart=' /root/.bashrc; cat <<'MS_SC_ALIAS_EOF'
alias dcrestart='if systemctl is-enabled -q metalsoft-sc 2>/dev/null; then echo restart metalsoft-sc.service; systemctl restart metalsoft-sc; else echo cd /opt/metalsoft/agents and restart docker compose;cd /opt/metalsoft/agents; docker compose down;sleep 2;docker compose up -d;cd -; fi'
MS_SC_ALIAS_EOF
    } > /root/.bashrc.new && cat /root/.bashrc.new > /root/.bashrc && debuglog "Updated the dcrestart alias in /root/.bashrc for metalsoft-sc.service"
    rm -f /root/.bashrc.new
  fi
  if grep -q '^Airgapped image upgrades: drop' /etc/ssh/ms_banner 2>/dev/null \
    && grep -q 'autoprocessing_<name>\.log$' /etc/ssh/ms_banner; then
    sed '/^Airgapped image upgrades: drop/,/autoprocessing_<name>\.log$/d' /etc/ssh/ms_banner | cat -s > /etc/ssh/ms_banner.new \
      && cat /etc/ssh/ms_banner.new > /etc/ssh/ms_banner && debuglog "Removed the drop-folder note from /etc/ssh/ms_banner"
    rm -f /etc/ssh/ms_banner.new
  fi

  # OVA: the network hook must not run compose behind the unit's back (the new one updates .env and try-restarts)
  local hook=/etc/networkd-dispatcher/routable.d/50-ms-ifup-hooks
  if [ -f "$hook" ] && ! grep -q 'metalsoft-sc.service' "$hook"; then
    # backup outside routable.d: networkd-dispatcher runs every executable in that directory
    cp -p "$hook" "/root/50-ms-ifup-hooks.orig-$(date +%Y%m%d%H%M%S)" 2>/dev/null
    cat > "$hook" <<'MS_SC_HOOK_EOF'
#!/bin/bash

# MetalSoft network interface up hook
# This script runs when network interfaces become routable

LOGFILE="/var/log/ms_network.log"
LOCKFILE="/tmp/ms-ifup-hook.lock"

# Function to log with timestamp
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$$] $*" >> "$LOGFILE"
}

# Skip loopback interface as it doesn't need nameserver reconfiguration
# Check this BEFORE any lockfile operations to avoid touching the lockfile
if [ "$IFACE" = "lo" ]; then
    log "Skipping loopback interface"
    exit 0
fi

# Detect main interface (the one with default route) and only run for that interface
main_iface=$(ip r get 1 2>/dev/null | head -1 | awk '{print $5}')
main_ip=$(ip r get 1 2>/dev/null | head -1 | awk '{print $7}')

if [ -z "$main_iface" ] && [ -n "$main_ip" ]; then
    # Fallback: try to get interface from main IP
    main_iface=$(ip addr show | grep "inet.*$main_ip" | awk '{print $NF}' | head -1)
fi

if [ "$IFACE" != "$main_iface" ]; then
    log "Skipping non-main interface $IFACE (main interface: $main_iface)"
    exit 0
fi

log "Processing main interface: $main_iface (IP: $main_ip)"

# Use flock for proper atomic locking
exec 200>"$LOCKFILE"
if ! flock -n 200; then
    log "Another instance is running, skipping execution"
    exit 0
fi

# Lock acquired successfully, record timestamp and PID
echo "$(date +%s) $$" > "$LOCKFILE"
trap 'flock -u 200; rm -f "$LOCKFILE"' EXIT

log "=== Network interface hook triggered ==="
log "Triggered by: $IFACE ($STATE), Processing main interface: $main_iface"

# Point the SC at the main IP (SITE_CONTROLLER_IP, NFS_HOST). Idempotent: nothing is written or restarted
# when the values are already right, so repeated "routable" events (DHCP renew, link flap) are no-ops.
AGENTS_DIR=/opt/metalsoft/agents
SC_UNIT=metalsoft-sc.service
# Enabled, not just installed: an SC whose unit was disabled is run with plain compose again.
if [ -n "$main_ip" ] && [ -d "$AGENTS_DIR" ] && systemctl is-enabled -q "$SC_UNIT" 2>/dev/null; then
    # SC managed by metalsoft-sc.service (sc-ctl.sh): the IPs live in .env, and the unit validates, starts and
    # health-checks the stack. Never run compose here: it would bypass the unit (and its extra compose files).
    envf="$AGENTS_DIR/.env"
    # sc-ctl.sh rewrites .env while it applies a GC bundle: take its lock so neither write is lost.
    if [ -d "$AGENTS_DIR/run" ]; then
        exec 201>>"$AGENTS_DIR/run/lock"
        flock -w 300 201 || log "sc-ctl.sh still holds $AGENTS_DIR/run/lock after 300s; updating .env anyway"
    fi
    cur_ip=$(sed -n 's/^SITE_CONTROLLER_IP=//p' "$envf" 2>/dev/null | tail -1)
    cur_nfs=$(sed -n 's/^NFS_HOST=//p' "$envf" 2>/dev/null | tail -1)
    if [ "$cur_ip" != "$main_ip" ] || [ "$cur_nfs" != "$main_ip:/data" ]; then
        tmp=$(mktemp "$AGENTS_DIR/.env.XXXXXX")
        grep -vE '^(SITE_CONTROLLER_IP|NFS_HOST)=' "$envf" 2>/dev/null >"$tmp"
        printf 'SITE_CONTROLLER_IP=%s\nNFS_HOST=%s:/data\n' "$main_ip" "$main_ip" >>"$tmp"
        chmod 0600 "$tmp" && mv -f "$tmp" "$envf"
        log "$envf: SITE_CONTROLLER_IP ${cur_ip:-<unset>} -> $main_ip, NFS_HOST ${cur_nfs:-<unset>} -> $main_ip:/data"
        # .env only reaches the containers where compose references ${SITE_CONTROLLER_IP} / ${NFS_HOST}.
        if grep -qE -- '- (SITE_CONTROLLER_IP|NFS_HOST)=[^$]' "$AGENTS_DIR"/docker-compose*.yaml 2>/dev/null; then
            log "WARNING: a compose file in $AGENTS_DIR sets SITE_CONTROLLER_IP/NFS_HOST literally; the new IP has no effect there"
        fi
        exec 201>&-  # release: the restart's prestart needs the lock
        # Restarts only a running unit; at boot the unit starts after docker and reads the new .env itself.
        systemctl try-restart "$SC_UNIT" && log "$SC_UNIT: try-restart done"
    else
        log "SC IP unchanged ($main_ip); nothing to do"
    fi
    exec 201>&-
elif [ -n "$main_ip" ] && [ -w "$AGENTS_DIR/docker-compose.yaml" ] && grep -q '\- NFS_HOST=' "$AGENTS_DIR/docker-compose.yaml"; then
    # SC deployed with docker compose only (deploy-agents.sh): same as before, but the compose file is only
    # rewritten when an IP differs. 'compose up -d' changes nothing when the stack already runs this config.
    if ! grep -q -- "- NFS_HOST=$main_ip:/data\$" "$AGENTS_DIR/docker-compose.yaml" \
       || ! grep -q -- "- SITE_CONTROLLER_IP=$main_ip\$" "$AGENTS_DIR/docker-compose.yaml"; then
        sed -i "s/- NFS_HOST=.*/- NFS_HOST=$main_ip:\/data/g" "$AGENTS_DIR/docker-compose.yaml"
        sed -i "s/- SITE_CONTROLLER_IP=.*/- SITE_CONTROLLER_IP=$main_ip/g" "$AGENTS_DIR/docker-compose.yaml"
        log "$AGENTS_DIR/docker-compose.yaml: SITE_CONTROLLER_IP and NFS_HOST set to $main_ip"
    fi
    docker compose -h &>/dev/null && cd "$AGENTS_DIR" && docker compose up -d &>> "$LOGFILE"
fi

# Reconfigure nameservers based on netplan configuration
log "Starting nameserver reconfiguration"

resolv="/etc/resolv.conf"
tmpfile=$(mktemp)

# Check if yq is available for YAML parsing
if ! command -v yq >/dev/null 2>&1; then
    log "yq not found, skipping nameserver reconfiguration"
    exit 0
fi

# Get new nameservers from Netplan
log "Extracting nameservers from netplan configuration"
mapfile -t new_ns < <(yq '.network.ethernets.*.nameservers.addresses[]' /etc/netplan/*.yaml 2>/dev/null)

if [ ${#new_ns[@]} -eq 0 ]; then
    log "No nameservers found in netplan, using defaults"
    new_ns=("8.8.8.8" "1.1.1.1")
fi

# Output new nameservers
log "Configuring nameservers: ${new_ns[*]}"
for ns in "${new_ns[@]}"; do
    echo "nameserver $ns"
done > "$tmpfile"

# Add rest of original resolv.conf (without nameserver lines)
if [ -f "$resolv" ]; then
    grep -v '^nameserver ' "$resolv" >> "$tmpfile"
    log "Preserved non-nameserver entries from existing resolv.conf"
fi

# Replace resolv.conf
if mv "$tmpfile" "$resolv"; then
    log "Successfully updated $resolv"
else
    log "ERROR: Failed to update $resolv"
    rm -f "$tmpfile"
    exit 1
fi
chmod 644 /etc/resolv.conf

log "Nameserver reconfiguration completed"

log "=== Network interface hook finished ==="
MS_SC_HOOK_EOF
    chmod 0755 "$hook"
    debuglog "Updated $hook for metalsoft-sc.service"
  fi
}

yamltojson ()
{
  python3 -c "import yaml;import json; yml = yaml.safe_load(open('$1')); x = json.dumps(yml); print(x)"
}

# develop* tags compare as newest (v1000.0.0)
verlte() {
  printf '%s\n' "${1/#develop*/v1000.0.0}" "${2/#develop*/v1000.0.0}" | sort -C -V
}

verlt() {
  ! verlte "$2" "$1"
}

testOS ()
{
  if [ -f /etc/os-release ]; then
    source /etc/os-release
    echo "$ID_LIKE" | grep -E -i -q "rhel|fedora" &&  found_os=rhel
    echo "$ID_LIKE" | grep -i -q debian && found_os=debian
  fi

  if [ -n "$found_os" ]; then
    if [ "$found_os" == "rhel" ]; then
      command -v yum > /dev/null && os_packager=yum
      command -v dnf > /dev/null && os_packager=dnf
      if echo "$ID"|grep -qoP '(rocky|almalinux)' && echo "$VERSION_ID"|grep -Po '\d+\.\d+'|grep -Pq "(^8\.9|^9\.3)"; then
        found_os_ver="rocky"
        test -n "$os_packager" && os_supported=1
      elif echo "$ID"|grep -qoP '(rhel|centos)' && echo "$VERSION_ID"|grep -Po '\d+\.\d+'|grep -Pq "(^9)"; then
        found_os_ver="rhel9"
        test -n "$os_packager" && os_supported=1
      fi

    elif [ "$found_os" == "debian" ]; then
      command -v apt > /dev/null && os_packager=apt
      command -v apt-get > /dev/null && os_packager=apt-get
      if echo "$ID"|grep -qoP '(ubuntu)' && echo "$VERSION_ID"|grep -Po '\d+\.\d+'|grep -Pq "(20\.04|22\.04)"; then
        found_os_ver="ubuntuLTS"
        test -n "$os_packager" && os_supported=1
      fi
    fi
    _all="$ID $VERSION_ID $found_os $os_packager"
    local array=($_all)
    echo "${array[@]}"
  else

    echo
    echo "This script is only compatible with Ubuntu 20+ OS, and RedHat 9+ OS"
    echo "and will not run on any other OS"
    echo
    exit 2
  fi
}
read -r NAME VERSION_ID found_os os_packager < <(testOS)

test -n "$IMAGES_TAG" || { echo -e "${lightred}Error: IMAGES_TAG not set (e.g. IMAGES_TAG=v7.4.0)${nc}" >&2; exit 12; }
verlt "$IMAGES_TAG" v7.0.0 && { echo -e "${lightred}Error: IMAGES_TAG=${IMAGES_TAG} not supported, v7.0.0+ required${nc}" >&2; exit 13; }

DOCKERBIN='docker'
test "$USEPODMAN" == "1" && DOCKERBIN='podman'

# SC_SYSTEMD=1: the stack runs under metalsoft-sc.service (sc-ctl.sh: GC bundles, health checks, rollback).
# Sticky: without SC_SYSTEMD, a re-run keeps the mode the SC already has; SC_SYSTEMD=0 switches back to plain compose.
case "${SC_SYSTEMD:-}" in
  '') if systemctl is-enabled -q metalsoft-sc.service 2>/dev/null; then SC_SYSTEMD=1; else SC_SYSTEMD=0; fi ;;
  1|true|yes) SC_SYSTEMD=1 ;;
  0|false|no) SC_SYSTEMD=0 ;;
  *) echo -e "${lightred}Error: SC_SYSTEMD=${SC_SYSTEMD} - use 1 (metalsoft-sc.service) or 0 (plain compose)${nc}" >&2; exit 14 ;;
esac

debuglog "OS: ${yellow}$NAME $VERSION_ID${nc} / ${yellow}$os_packager${nc} for ${yellow}$found_os${nc} / ${lightgreen}$DOCKERBIN${nc} / whoami: ${pink}$(whoami)${nc}"
if [ "$found_os" == "debian" ];then
  export LC_ALL=C
  export DEBIAN_FRONTEND=noninteractive
  export APT_LISTCHANGES_FRONTEND=none

  command -v curl  > /dev/null && command -v update-ca-certificates > /dev/null && command -v jq > /dev/null && command -v ip > /dev/null && command -v tar > /dev/null || { debuglog "Installing required packages" && \
    $os_packager update -qq && \
    $os_packager -y install curl ca-certificates net-tools jq dnsutils iproute2 gzip tar >/dev/null || debuglog "Error installing packages"; }
    else # if rhel
      command -v curl  > /dev/null && command -v update-ca-trust > /dev/null && command -v jq > /dev/null && command -v netstat > /dev/null && command -v tar > /dev/null || { debuglog "Installing required packages" && \
        $os_packager -qy install curl ca-certificates bind-utils iproute jq nmap-ncat wget net-tools gzip tar >/dev/null || debuglog "Error installing packages" fail; }
fi

debuglog "Creating folders"
mkdir -p /opt/metalsoft/agents /opt/metalsoft/containerd /opt/metalsoft/nfs-storage/buildImageRequest /opt/metalsoft/ansible-jobs /opt/metalsoft/ansible-archives /opt/metalsoft/pdns || { echo "ERROR: unable to create folders in /opt/"; exit 3; }
chown -R 1000:1000 /opt/metalsoft/ansible-jobs /opt/metalsoft/ansible-archives /opt/metalsoft/nfs-storage
if ! grep -q '^alias a=' /root/.bashrc;then echo "alias a='cd /opt/metalsoft/agents'" >> /root/.bashrc || true;fi

REG_HOST=${REGISTRY_HOST:-"registry.metalsoft.dev"}
IMAGES_TAGENV='${TAG}'
MSAGENT_URL="${REG_HOST}/sc/ms-agent:${IMAGES_TAGENV}"
ANSIBLE_RUNNER_URL="${REG_HOST}/sc/sc-ansible-playbook-runner:${IMAGES_TAGENV}"
SCIMAGEBUILDER_URL="${REG_HOST}/sc/image-builder:${IMAGES_TAGENV}"
verlt "$IMAGES_TAG" v8.0.0 && SCIMAGEBUILDER_URL="${REG_HOST}/sc/sc-image-builder:${IMAGES_TAGENV}"

# Metrics pusher image (ENVVAR_ENABLE_METRICS=enabled); docker.io/victoriametrics/vmagent mirrored on the MetalSoft registry
VMAGENT_URL="${VMAGENT_URL:-${REG_HOST}/hub_docker_com/victoriametrics/vmagent:v1.149.0}"

MS_TUNNEL_SECRET="${MS_TUNNEL_SECRET:-default}"

# Env vars set via CLI:
CLI_DATACENTERNAME="$DATACENTERNAME"

# Get network interface information
# Check for default ipv6 IP and IF
interface_ip="$(ip -6 route get 2001:4860:4860::8888 2>/dev/null | awk '/src/ {for(i=1;i<=NF;i++) if ($i=="src") print $(i+1)}'|head -1)"
if [ -z "$interface_ip" ]; then
    # no default IPv6 found, checking IPv4:
  default_route="$(ip r get 1 2>/dev/null | head -1)"
  interface_ip="$(echo "$default_route" | awk '{print $7}')"
  test -n "$interface_ip" && interface_name="$(ip -br a 2>/dev/null | grep "\b${interface_ip}\b" | awk '{print $1}')"
else # we have a default IPv6
  interface_name="$(ip -6 route show default 2>/dev/null | head -1 |awk '{print $5}')"
fi

interface_name="${ENV_INTERFACE_NAME:-$interface_name}"
interface_ip="${ENV_INTERFACE_IP:-$interface_ip}"
test -z "$interface_name" && echo "Error: no interface found. use ENV_INTERFACE_NAME to set one" >&2 && exit 6
test -z "$interface_ip" && echo "Error: no interface IP found, use ENV_INTERFACE_IP to set one" >&2 && exit 7

debuglog "Using interface ${interface_name} with IP ${interface_ip}"

# Try multiple methods to get main IP address. Prioritize the IP on the default route interface.
MAINIP="$interface_ip"

test -n "$SSL_HOSTNAME" || { echo -e "${lightred}Error: SSL_HOSTNAME not set${nc}" >&2; exit 11; }
NFSIP="$MAINIP"

# keep the NFS_HOST if already set, as it could've been modified manually
# keep the NFS IP of an existing install: .env (SC_SYSTEMD=1 compose only has ${NFS_HOST}), else the compose file
_nfsip="$( { grep -Po "^NFS_HOST='?\K[^:']*" /opt/metalsoft/agents/.env; grep -Po 'NFS_HOST=\K[^\:]*' /opt/metalsoft/agents/docker-compose.yaml; } 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)"
test -n "$_nfsip" && NFSIP="$_nfsip"

if [ -n "$https_proxy" ];then curl_s_proxy="--proxy $https_proxy"; elif [ -n "$HTTPS_PROXY" ];then curl_s_proxy="--proxy $HTTPS_PROXY"; fi
if [ -n "$http_proxy" ];then curl_proxy="--proxy $http_proxy"; elif [ -n "$HTTP_PROXY" ];then curl_proxy="--proxy $HTTP_PROXY"; fi


function check_remote_conn {
  local ip=$1
  local port=$2
  local protocol=${3:-tcp}
  [ -n "$4" ] && local comment="$4 "
  [ "$protocol" = "icmp" ] && local port=icmp

  echo -en "Check connection from ${bold}${MAINIP}${nc} to ${comment}${orange}$ip:$port${nc}... "

  # Start spinner animation in background
  local __spinner_pid
  local __spinner_chars='/-\|'
  {
    local i=0
    while true; do
      printf "\b%s" "${__spinner_chars:$((i % 4)):1}"
      sleep 0.1
      i=$((i + 1))
    done
  } &
  __spinner_pid=$!
  _stop_spinner() { kill $__spinner_pid 2>/dev/null; wait $__spinner_pid 2>/dev/null; printf "\b"; }

  # For HTTPS (port 443), use hostname directly without IP resolution
  if [ "$protocol" = "tcp" ] && [ "$port" = "443" ]; then
    if curl -sk --connect-timeout 10 --max-time 11 $curl_s_proxy "https://$ip" >/dev/null 2>&1; then
      _stop_spinner
      echo -e "${lightgreen}success${nc}"
      return 0
    else
      _stop_spinner
      echo -e "${yellow}failure${nc}"
      return 1
    fi
  elif [ "$protocol" = "tcp" ] && [ "$port" = "80" ]; then
    if curl -sk --connect-timeout 10 --max-time 11 $curl_proxy "http://$ip" >/dev/null 2>&1; then
      _stop_spinner
      echo -e "${lightgreen}success${nc}"
      return 0
    else
      _stop_spinner
      echo -e "${yellow}failure${nc}"
      return 1
    fi
  elif [ "$protocol" = "icmp" ]; then
    if ping -c1 "$ip" >/dev/null 2>&1; then
      _stop_spinner
      echo -e "${lightgreen}success${nc}"
      return 0
    else
      _stop_spinner
      echo -e "${yellow}failure${nc}"
      return 1
    fi
  fi

  # For other protocols, resolve to IP
  case "$ip" in
    *[!0-9.]*)
      # Try getent first (more portable), fall back to dig if available
      if command -v getent >/dev/null 2>&1; then
        ip=$(getent ahosts "$ip" 2>/dev/null | awk '/STREAM/ {print $1; exit}')
      fi
      if [ -z "$ip" ] && command -v dig >/dev/null 2>&1; then
        ip=$(dig +short "$ip" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | xargs)
      fi
      ;;
  esac

  if [ -z "$ip" ]; then
    _stop_spinner
    echo -e "${yellow}Error: not resolved${nc}"
    return 1
  fi

  local success_count=0
  local total_count=0
  res=""
  for ip in $ip; do
    total_count=$((total_count + 1))
    if [ "$protocol" = "tcp" ]; then
      if (echo >/dev/tcp/"$ip"/"$port") >/dev/null 2>&1; then
        res+="${lightgreen}$ip=success${nc} "
        success_count=$((success_count + 1))
      else
        res+="${yellow}$ip=failure${nc} "
      fi
    else
      if (echo >/dev/udp/"$ip"/"$port") >/dev/null 2>&1; then
        res+="${lightgreen}$ip=success${nc} "
        success_count=$((success_count + 1))
      else
        res+="${yellow}$ip=failure${nc} "
      fi
    fi
  done
  _stop_spinner
  echo -e "${res% }"

  # Return success only if all connections succeeded
  [ "$success_count" -eq "$total_count" ] && return 0 || return 1
}

echo -e "${orange}Note:${nc} connectivity checks are informational — failures will not block setup."
#check_remote_conn download.docker.com 443 tcp
check_remote_conn "${REG_HOST}" 443 tcp || REG_HOST_CONN_FAILED=1
test -n "$SSL_HOSTNAME" && check_remote_conn "${SSL_HOSTNAME}" 443 tcp
test -n "$SSL_HOSTNAME" && check_remote_conn "${SSL_HOSTNAME}" 0 icmp

function manageSSL
{
  test -n "${SSL_PULL_URL}" && curl -skL --connect-timeout 20 $curl_s_proxy "${SSL_PULL_URL}" |tee /root/agents-ssl.pem.tmp && openssl x509 -in /root/agents-ssl.pem.tmp -text -nocert|grep -q 'Not Before:' && mv /root/agents-ssl.pem.tmp /root/agents-ssl.pem || { rm -f /root/agents-ssl.pem.tmp; echo "Error pulling certificate"; }
  test -f /root/agents-ssl.pem && echo "Found /root/agents-ssl.pem. Checking.." && openssl x509 -in /root/agents-ssl.pem -text -nocert|grep -q 'Not Before:' && ssl=/root/agents-ssl.pem
  test -z "${ssl}" && debuglog "Please provide path of the SSL pem:" && read -r -e -p "Path to SSL pem: " ssl
  if [ -r "$ssl" ];then
    DISCOVERED_SSL_HOSTNAMES="$(openssl x509 -in "$ssl" -noout -text 2>/dev/null|grep DNS:|head -1)"
    DISCOVERED_SSL_HOSTNAME="$(echo "$DISCOVERED_SSL_HOSTNAMES"|sed 's/,\s\+/\n/g;'|sed 's/.*DNS://g'|cut -d. -f2-10|head -1)"
    if [ -z "$DISCOVERED_SSL_HOSTNAME" ];then
      debuglog "WARNING: no hostname discovered in SSL file" bold yellow
      # return 1
    fi
    if cp "$ssl" /opt/metalsoft/agents/ssl-cert.pem;then
      debuglog "copied $ssl to /opt/metalsoft/agents/ssl-cert.pem. Found SSL hosts: $DISCOVERED_SSL_HOSTNAMES"
      return 0
    else
      echo Error: could not copy "$ssl"
      return 1

    fi
  else
    echo "Error: no valid path provided or missing SSL_PULL_URL"
    return 1
  fi
}


test ! -f /usr/local/share/ca-certificates/metalsoft_ca.crt && mkdir -p /usr/local/share/ca-certificates/ && \
  cat > /usr/local/share/ca-certificates/metalsoft_ca.crt <<ENDD
-----BEGIN CERTIFICATE-----
MIIEBzCCAu+gAwIBAgIUTObwqnwPcZW4sZ5RvTl++4G/4+EwDQYJKoZIhvcNAQEL
BQAwgZIxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJJTDEQMA4GA1UEBwwHQ2hpY2Fn
bzEcMBoGA1UECgwTTWV0YWxzb2Z0IENsb3VkIEluYzELMAkGA1UECwwCSVQxFTAT
BgNVBAMMDG1ldGFsc29mdC5pbzEiMCAGCSqGSIb3DQEJARYTc3lzb3BzQG1ldGFs
c29mdC5pbzAeFw0yMjA1MjEwODEyNDNaFw0yNzA1MjAwODEyNDNaMIGSMQswCQYD
VQQGEwJVUzELMAkGA1UECAwCSUwxEDAOBgNVBAcMB0NoaWNhZ28xHDAaBgNVBAoM
E01ldGFsc29mdCBDbG91ZCBJbmMxCzAJBgNVBAsMAklUMRUwEwYDVQQDDAxtZXRh
bHNvZnQuaW8xIjAgBgkqhkiG9w0BCQEWE3N5c29wc0BtZXRhbHNvZnQuaW8wggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDp42R+t6p23lhjppq83K2b3mbf
2KLIQ5IncUr0vgPp0NtWDbPFfK5HSWy0x62Gtux5SkmPOt3FwS0r1/BqgLrgM5rP
ZTPpf/t0jSSh0vnCBP47XmPq4kDNF8rpxCgCoxEH+JWjdnJLBAO72qNdP5h2eAq1
rFuwy71BFAC+qL9o64d/H0IJ4SHj9h1y2gnq7gAyiyLF7kw/PTXD5OA4zonrmBwL
JdYmvXxmJjgi4W86X48pCdLowxFk5skZQTGSXZLcoblDXWRSwrc3s65EDhP53FVC
qNjD1fxAV6fkLwkp8C0JXqQ+0vn3PBu7BO6MwZE5OgnWjq93FXHULDkpRlbDAgMB
AAGjUzBRMB0GA1UdDgQWBBRsQNxcbzofE3L9TIiLqon4J+/ACTAfBgNVHSMEGDAW
gBRsQNxcbzofE3L9TIiLqon4J+/ACTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3
DQEBCwUAA4IBAQAXiLcar3aHHL8el2auZB6BqWUWLmTYUyTC6bizWvn+vhe4bpNC
4lRVrCityEecX2VzbR7WVOa2j5GwStoaJPDFeZf1ESN/HvTl9n4B7eInB7u/qb/g
QWsValgGyvfMdk4MDFOTigoEM3XBdXkAq/PwAipr7BpoKDSltArLbG2pxC0A61lo
3/i8Zqf4XhAAHUyS4bx7VmapY6wfE6bBh5ckijrenhsvO5u52oXJWDXo0TJM+x0L
pmN4bRq+IcraOaLIwVmon9ggvO4Cjt+V9cF99SHB/jawlflX/XL3DVvapT3sKJYo
dvVIE0i3gwt0+qhni75EgUbufGrVlO5aC1BK
-----END CERTIFICATE-----
ENDD

debuglog "Ensuring Metalsoft CA is installed"
test "$found_os" == "debian" && test ! -f /usr/local/share/ca-certificates/metalsoft_ca.crt && curl -skL $curl_s_proxy https://repo.metalsoft.io/.tftp/metalsoft_ca.crt -o /usr/local/share/ca-certificates/metalsoft_ca.crt
test "$found_os" == "debian" && test ! -f /etc/ssl/certs/metalsoft_ca.crt && cp /usr/local/share/ca-certificates/metalsoft_ca.crt /etc/ssl/certs/ && update-ca-certificates >/dev/null

test "$found_os" == "rhel" && test ! -f /etc/pki/ca-trust/source/anchors/metalsoft_ca.crt && curl -skL $curl_s_proxy https://repo.metalsoft.io/.tftp/metalsoft_ca.crt -o /etc/pki/ca-trust/source/anchors/metalsoft_ca.crt
test "$found_os" == "rhel" && test -f /etc/pki/ca-trust/source/anchors/metalsoft_ca.crt && cp /etc/pki/ca-trust/source/anchors/metalsoft_ca.crt /etc/ssl/certs/ && update-ca-trust extract >/dev/null

debuglog "Checking for other custom CAs"
if [ "$found_os" == "debian" ];then
  if [[ -n "$CUSTOM_CA" ]]; then
    echo "${CUSTOM_CA_CERT}" | base64 -d| gunzip -c 2>/dev/null > "/usr/local/share/ca-certificates/${CUSTOM_CA}" || echo "${CUSTOM_CA_CERT}" | base64 -d > "/usr/local/share/ca-certificates/${CUSTOM_CA}"
    cp "/usr/local/share/ca-certificates/${CUSTOM_CA}" /etc/ssl/certs/
    update-ca-certificates >/dev/null
  fi
  ms_agent_ssl_os_ca_path="/etc/ssl/certs"
else # if rhel
  if [[ -n "$CUSTOM_CA" ]]; then
    echo "${CUSTOM_CA_CERT}" | base64 -d| gunzip -c 2>/dev/null > "/etc/pki/ca-trust/source/anchors/${CUSTOM_CA}" || echo "${CUSTOM_CA_CERT}" | base64 -d > "/etc/pki/ca-trust/source/anchors/${CUSTOM_CA}"
    cp "/etc/pki/ca-trust/source/anchors/${CUSTOM_CA}" /etc/ssl/certs/
    restorecon -R /etc/ssl/certs/
    restorecon -R /etc/pki/ca-trust/source/anchors/
    # https://stackoverflow.com/a/31334443/2291328
    chcon -Rt svirt_sandbox_file_t /etc/ssl/certs/
    if ! semanage fcontext -l | grep -q -E "^/etc/ssl/certs(/.*)?"; then
      semanage fcontext -a -t svirt_sandbox_file_t "/etc/ssl/certs(/.*)?"
    fi
    update-ca-trust extract
  fi
  ms_agent_ssl_os_ca_path="/etc/pki/ca-trust/source/anchors"
  # or (This ensures the rule is set correctly, whether it existed before or not.)
  # semanage fcontext -m -t svirt_sandbox_file_t "/etc/ssl/certs(/.*)?"

fi

# The systemd-managed SC (metalsoft-sc.service, sc-ctl.sh) also writes these files and restarts the containers:
# stop it while this script runs, start it again at the end.
if [ "$SC_SYSTEMD" != 1 ] && systemctl is-enabled -q metalsoft-sc.service 2>/dev/null; then
  debuglog "SC_SYSTEMD=0: disabling metalsoft-sc.service, back to plain $DOCKERBIN compose"
  systemctl disable -q --now metalsoft-sc.service || true
elif systemctl is-active -q metalsoft-sc.service 2>/dev/null; then
  debuglog "Stopping metalsoft-sc.service while deploying"
  # Started again however this script ends (an early 'exit' included), so the SC is never left down.
  systemctl stop metalsoft-sc.service && trap 'debuglog "Starting metalsoft-sc.service again"; systemctl start metalsoft-sc.service || debuglog "metalsoft-sc.service did not start; check: journalctl -u metalsoft-sc" fail' EXIT
fi

backupPrefix="backup-$(date +"%Y%m%d%H%M%S")"
# Create backup of config files if they exist (0600: docker-compose.yaml holds AGENT_SECRET, ssl-cert.pem a private key)
for file in docker-compose.yaml ssl-cert.pem .env; do
  if [ -f "/opt/metalsoft/agents/$file" ]; then
    install -m 0600 "/opt/metalsoft/agents/$file" "/opt/metalsoft/agents/${backupPrefix}-${file#.}.bak"
  fi
done
chmod 0600 /opt/metalsoft/agents/backup-*.bak 2>/dev/null || true # older backups were 0644

if ! command -v yq >/dev/null; then
  # Get latest yq version from GitHub API
  YQ_VERSION=$(curl -sSL $curl_s_proxy https://api.github.com/repos/mikefarah/yq/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
  # Fallback to known working version if API call fails
  YQ_VERSION="${YQ_VERSION:-v4.45.4}"

  YQ_ARCH=$(uname -m)
  case "$YQ_ARCH" in
    "x86_64") YQ_ARCH="amd64" ;;
    "aarch64" | "arm64") YQ_ARCH="arm64" ;;
    *) echo "yq installation: Unsupported architecture: $YQ_ARCH"; exit 1 ;;
  esac

  YQ_URL="https://github.com/mikefarah/yq/releases/download/${YQ_VERSION}/yq_linux_${YQ_ARCH}"
  debuglog "Installing yq ${YQ_VERSION} for ${YQ_ARCH}"
  curl -sSL $curl_s_proxy -o /usr/local/bin/yq "${YQ_URL}"
  chmod +x /usr/local/bin/yq
fi

  debuglog "Enabling nfs/nfsd kernel modules"
  if [ "$found_os" == "debian" ];then
    if [[ -f /usr/lib/modules/$(uname -r)/kernel/fs/nfs/nfs.ko || -f /usr/lib/modules/$(uname -r)/kernel/fs/nfs/nfs.ko.zst ]];then
      modprobe nfs && \
        if ! grep -qE '^nfs$' /etc/modules 2>/dev/null;then echo nfs >> /etc/modules;fi
      else
        echo "no nfs kernel module found in current kernel modules, needed for $DOCKERBIN nfs container" && exit 1
    fi
    if [[ -f /usr/lib/modules/$(uname -r)/kernel/fs/nfsd/nfsd.ko || -f /usr/lib/modules/$(uname -r)/kernel/fs/nfsd/nfsd.ko.zst ]];then
      modprobe nfsd && \
        if ! grep -qE '^nfsd$' /etc/modules 2>/dev/null;then echo nfsd >> /etc/modules;fi
      else
        echo "no nfsd kernel module found in current kernel modules, needed for $DOCKERBIN nfs container" && exit 1
    fi
  else # if rhel
    if [[ -f /usr/lib/modules/$(uname -r)/kernel/fs/nfs/nfs.ko || -f /usr/lib/modules/$(uname -r)/kernel/fs/nfs/nfs.ko.xz ]];then
      modprobe nfs && \
        if ! grep -qE '^nfs$' /etc/modules-load.d/*.conf 2>/dev/null;then echo nfs >> /etc/modules-load.d/nfs.conf;fi
      else
        echo "no nfs kernel module found in current kernel modules, needed for $DOCKERBIN nfs container" && exit 1
    fi
    if [[ -f /usr/lib/modules/$(uname -r)/kernel/fs/nfsd/nfsd.ko || -f /usr/lib/modules/$(uname -r)/kernel/fs/nfsd/nfsd.ko.xz ]];then
      modprobe nfsd && \
        if ! grep -qE '^nfsd$' /etc/modules-load.d/*.conf 2>/dev/null;then echo nfsd >> /etc/modules-load.d/nfs.conf;fi
      else
        echo "no nfsd kernel module found in current kernel modules, needed for $DOCKERBIN nfs container" && exit 1
    fi
 fi

  test -d /usr/share/keyrings && test ! -f /usr/share/keyrings/docker-archive-keyring.gpg && \
    cat > /tmp/docker-archive-keyring.gpg <<ENDD
-----BEGIN PGP PUBLIC KEY BLOCK-----

mQINBFit2ioBEADhWpZ8/wvZ6hUTiXOwQHXMAlaFHcPH9hAtr4F1y2+OYdbtMuth
lqqwp028AqyY+PRfVMtSYMbjuQuu5byyKR01BbqYhuS3jtqQmljZ/bJvXqnmiVXh
38UuLa+z077PxyxQhu5BbqntTPQMfiyqEiU+BKbq2WmANUKQf+1AmZY/IruOXbnq
L4C1+gJ8vfmXQt99npCaxEjaNRVYfOS8QcixNzHUYnb6emjlANyEVlZzeqo7XKl7
UrwV5inawTSzWNvtjEjj4nJL8NsLwscpLPQUhTQ+7BbQXAwAmeHCUTQIvvWXqw0N
cmhh4HgeQscQHYgOJjjDVfoY5MucvglbIgCqfzAHW9jxmRL4qbMZj+b1XoePEtht
ku4bIQN1X5P07fNWzlgaRL5Z4POXDDZTlIQ/El58j9kp4bnWRCJW0lya+f8ocodo
vZZ+Doi+fy4D5ZGrL4XEcIQP/Lv5uFyf+kQtl/94VFYVJOleAv8W92KdgDkhTcTD
G7c0tIkVEKNUq48b3aQ64NOZQW7fVjfoKwEZdOqPE72Pa45jrZzvUFxSpdiNk2tZ
XYukHjlxxEgBdC/J3cMMNRE1F4NCA3ApfV1Y7/hTeOnmDuDYwr9/obA8t016Yljj
q5rdkywPf4JF8mXUW5eCN1vAFHxeg9ZWemhBtQmGxXnw9M+z6hWwc6ahmwARAQAB
tCtEb2NrZXIgUmVsZWFzZSAoQ0UgZGViKSA8ZG9ja2VyQGRvY2tlci5jb20+iQI3
BBMBCgAhBQJYrefAAhsvBQsJCAcDBRUKCQgLBRYCAwEAAh4BAheAAAoJEI2BgDwO
v82IsskP/iQZo68flDQmNvn8X5XTd6RRaUH33kXYXquT6NkHJciS7E2gTJmqvMqd
tI4mNYHCSEYxI5qrcYV5YqX9P6+Ko+vozo4nseUQLPH/ATQ4qL0Zok+1jkag3Lgk
jonyUf9bwtWxFp05HC3GMHPhhcUSexCxQLQvnFWXD2sWLKivHp2fT8QbRGeZ+d3m
6fqcd5Fu7pxsqm0EUDK5NL+nPIgYhN+auTrhgzhK1CShfGccM/wfRlei9Utz6p9P
XRKIlWnXtT4qNGZNTN0tR+NLG/6Bqd8OYBaFAUcue/w1VW6JQ2VGYZHnZu9S8LMc
FYBa5Ig9PxwGQOgq6RDKDbV+PqTQT5EFMeR1mrjckk4DQJjbxeMZbiNMG5kGECA8
g383P3elhn03WGbEEa4MNc3Z4+7c236QI3xWJfNPdUbXRaAwhy/6rTSFbzwKB0Jm
ebwzQfwjQY6f55MiI/RqDCyuPj3r3jyVRkK86pQKBAJwFHyqj9KaKXMZjfVnowLh
9svIGfNbGHpucATqREvUHuQbNnqkCx8VVhtYkhDb9fEP2xBu5VvHbR+3nfVhMut5
G34Ct5RS7Jt6LIfFdtcn8CaSas/l1HbiGeRgc70X/9aYx/V/CEJv0lIe8gP6uDoW
FPIZ7d6vH+Vro6xuWEGiuMaiznap2KhZmpkgfupyFmplh0s6knymuQINBFit2ioB
EADneL9S9m4vhU3blaRjVUUyJ7b/qTjcSylvCH5XUE6R2k+ckEZjfAMZPLpO+/tF
M2JIJMD4SifKuS3xck9KtZGCufGmcwiLQRzeHF7vJUKrLD5RTkNi23ydvWZgPjtx
Q+DTT1Zcn7BrQFY6FgnRoUVIxwtdw1bMY/89rsFgS5wwuMESd3Q2RYgb7EOFOpnu
w6da7WakWf4IhnF5nsNYGDVaIHzpiqCl+uTbf1epCjrOlIzkZ3Z3Yk5CM/TiFzPk
z2lLz89cpD8U+NtCsfagWWfjd2U3jDapgH+7nQnCEWpROtzaKHG6lA3pXdix5zG8
eRc6/0IbUSWvfjKxLLPfNeCS2pCL3IeEI5nothEEYdQH6szpLog79xB9dVnJyKJb
VfxXnseoYqVrRz2VVbUI5Blwm6B40E3eGVfUQWiux54DspyVMMk41Mx7QJ3iynIa
1N4ZAqVMAEruyXTRTxc9XW0tYhDMA/1GYvz0EmFpm8LzTHA6sFVtPm/ZlNCX6P1X
zJwrv7DSQKD6GGlBQUX+OeEJ8tTkkf8QTJSPUdh8P8YxDFS5EOGAvhhpMBYD42kQ
pqXjEC+XcycTvGI7impgv9PDY1RCC1zkBjKPa120rNhv/hkVk/YhuGoajoHyy4h7
ZQopdcMtpN2dgmhEegny9JCSwxfQmQ0zK0g7m6SHiKMwjwARAQABiQQ+BBgBCAAJ
BQJYrdoqAhsCAikJEI2BgDwOv82IwV0gBBkBCAAGBQJYrdoqAAoJEH6gqcPyc/zY
1WAP/2wJ+R0gE6qsce3rjaIz58PJmc8goKrir5hnElWhPgbq7cYIsW5qiFyLhkdp
YcMmhD9mRiPpQn6Ya2w3e3B8zfIVKipbMBnke/ytZ9M7qHmDCcjoiSmwEXN3wKYI
mD9VHONsl/CG1rU9Isw1jtB5g1YxuBA7M/m36XN6x2u+NtNMDB9P56yc4gfsZVES
KA9v+yY2/l45L8d/WUkUi0YXomn6hyBGI7JrBLq0CX37GEYP6O9rrKipfz73XfO7
JIGzOKZlljb/D9RX/g7nRbCn+3EtH7xnk+TK/50euEKw8SMUg147sJTcpQmv6UzZ
cM4JgL0HbHVCojV4C/plELwMddALOFeYQzTif6sMRPf+3DSj8frbInjChC3yOLy0
6br92KFom17EIj2CAcoeq7UPhi2oouYBwPxh5ytdehJkoo+sN7RIWua6P2WSmon5
U888cSylXC0+ADFdgLX9K2zrDVYUG1vo8CX0vzxFBaHwN6Px26fhIT1/hYUHQR1z
VfNDcyQmXqkOnZvvoMfz/Q0s9BhFJ/zU6AgQbIZE/hm1spsfgvtsD1frZfygXJ9f
irP+MSAI80xHSf91qSRZOj4Pl3ZJNbq4yYxv0b1pkMqeGdjdCYhLU+LZ4wbQmpCk
SVe2prlLureigXtmZfkqevRz7FrIZiu9ky8wnCAPwC7/zmS18rgP/17bOtL4/iIz
QhxAAoAMWVrGyJivSkjhSGx1uCojsWfsTAm11P7jsruIL61ZzMUVE2aM3Pmj5G+W
9AcZ58Em+1WsVnAXdUR//bMmhyr8wL/G1YO1V3JEJTRdxsSxdYa4deGBBY/Adpsw
24jxhOJR+lsJpqIUeb999+R8euDhRHG9eFO7DRu6weatUJ6suupoDTRWtr/4yGqe
dKxV3qQhNLSnaAzqW/1nA3iUB4k7kCaKZxhdhDbClf9P37qaRW467BLCVO/coL3y
Vm50dwdrNtKpMBh3ZpbB1uJvgi9mXtyBOMJ3v8RZeDzFiG8HdCtg9RvIt/AIFoHR
H3S+U79NT6i0KPzLImDfs8T7RlpyuMc4Ufs8ggyg9v3Ae6cN3eQyxcK3w0cbBwsh
/nQNfsA6uu+9H7NhbehBMhYnpNZyrHzCmzyXkauwRAqoCbGCNykTRwsur9gS41TQ
M8ssD1jFheOJf3hODnkKU+HKjvMROl1DK7zdmLdNzA1cvtZH/nCC9KPj1z8QC47S
xx+dTZSx4ONAhwbS/LN3PoKtn8LPjY9NP9uDWI+TWYquS2U+KHDrBDlsgozDbs/O
jCxcpDzNmXpWQHEtHU7649OXHP7UeNST1mCUCH5qdank0V1iejF6/CfTFU4MfcrG
YT90qFF93M3v01BbxP+EIY2/9tiIPbrd
=0YYh
-----END PGP PUBLIC KEY BLOCK-----
ENDD

test -f /tmp/docker-archive-keyring.gpg && test -d /usr/share/keyrings && cat /tmp/docker-archive-keyring.gpg | gpg --batch --yes --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

debuglog "Ensuring $DOCKERBIN is installed"
if [ "$found_os" == "debian" ];then
  if [ "$DOCKERBIN" == "docker" ];then
    command -v docker > /dev/null || { debuglog "Install docker" && \
      echo   "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list && \
      debuglog "$os_packager update.." && \
      $os_packager update -qq && \
      debuglog "$os_packager installing docker-ce docker-ce-cli containerd.io docker-compose-plugin .." && \
      $os_packager -y install docker-ce docker-ce-cli containerd.io docker-compose-plugin >/dev/null; }
        else
          command -v podman > /dev/null || { debuglog "Install podman" && \
            $os_packager update -qq && \
            $os_packager install -y curl podman python3-dotenv >/dev/null && \
            curl $curl_proxy -sSO http://archive.ubuntu.com/ubuntu/pool/universe/g/golang-github-containernetworking-plugins/containernetworking-plugins_1.1.1+ds1-3build1_amd64.deb && dpkg -i containernetworking-plugins_1.1.1+ds1-3build1_amd64.deb >/dev/null && \
            curl $curl_s_proxy -sSo /usr/local/bin/podman-compose https://raw.githubusercontent.com/containers/podman-compose/main/podman_compose.py && chmod +x /usr/local/bin/podman-compose; }
  fi
else # if rhel
  if [ "$DOCKERBIN" == "docker" ];then
    command -v docker > /dev/null || { debuglog "Install docker" && \
      $os_packager config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo >/dev/null && \
      debuglog "$os_packager installing docker-ce docker-ce-cli containerd.io docker-compose-plugin .." && \
      $os_packager -y install docker-ce docker-ce-cli containerd.io docker-compose-plugin >/dev/null; }
        else
          dnf install -y podman python3-pip python3-yaml >/dev/null && python3 -m pip install python-dotenv >/dev/null
  fi
fi

debuglog "Checking if '$DOCKERBIN compose' is available"
if [ "$DOCKERBIN" == "docker" ];then
  docker compose &>/dev/null || { debuglog "$os_packager Installing docker-compose-plugin" && $os_packager update -qy && $os_packager -y install docker-compose-plugin; }
else
  podman-compose version &>/dev/null || { debuglog "Installing podman-compose" && curl $curl_s_proxy -sfo /usr/local/bin/podman-compose https://raw.githubusercontent.com/containers/podman-compose/main/podman_compose.py && chmod +x /usr/local/bin/podman-compose; }
fi

# Detect the GID that owns the docker socket (authoritative for container access),
# fall back to the docker group entry, then 999. Used as the group_add default below.
DOCKER_GID=""
if [ "$DOCKERBIN" == "docker" ]; then
  DOCKER_GID="$(stat -c '%g' /var/run/docker.sock 2>/dev/null)"
  test -z "$DOCKER_GID" && DOCKER_GID="$(getent group docker 2>/dev/null | cut -d: -f3)"
  debuglog "Detected DOCKER_GID=${DOCKER_GID:-999}"
fi
test -z "$DOCKER_GID" && DOCKER_GID=999

debuglog "Checking provided SSL"
test -n "$SSL_B64" && echo -n "$SSL_B64"|base64 -d > /opt/metalsoft/agents/ssl-cert.pem

if [ ! -f /opt/metalsoft/agents/ssl-cert.pem ];then
  SSL_PULL_URL="${SSL_PULL_URL}" manageSSL
  while [ $? -ne 0 ]; do
    manageSSL
  done
fi

if [ -z "$SSL_HOSTNAME" ];then
  read -r -p "Enter SSL hostname [${DISCOVERED_SSL_HOSTNAME}]: " name
  SSL_HOSTNAME=${name:-$DISCOVERED_SSL_HOSTNAME}
  debuglog "SSL_HOSTNAME set to: $SSL_HOSTNAME"
fi

test -n "$DATACENTERNAME" || { echo -e "${lightred}Error: DATACENTERNAME is not set${nc}" >&2; exit 1; }

HOSTNAMERANDOM=$(echo ${RANDOM} | md5sum | head -c 3)
HOSTNAMERANDOM=$(echo "$interface_ip"|sed 's/[.:][.:]*/-/g')-${HOSTNAMERANDOM}
while [[ "$HOSTNAMERANDOM" == *[.:]* ]]; do HOSTNAMERANDOM=${HOSTNAMERANDOM//[.:]/-}; done
while [[ "$HOSTNAMERANDOM" == *--* ]]; do HOSTNAMERANDOM=${HOSTNAMERANDOM//--/-}; done
# Keep the agent's identity across re-runs: reuse the AGENT_ID of an existing install for the same datacenter
# (from .env, or from a compose file that still holds the literal value).
_prev_id="$( { grep -Po "^AGENT_ID='?\K[^']*" /opt/metalsoft/agents/.env; grep -Po '^\s+- AGENT_ID=\K[^$].*' /opt/metalsoft/agents/docker-compose.yaml; } 2>/dev/null | head -1)"
if [[ $_prev_id == "${DATACENTERNAME}-"* && ${_prev_id#"${DATACENTERNAME}-"} =~ ^[A-Za-z0-9-]+$ ]]; then
  HOSTNAMERANDOM="${_prev_id#"${DATACENTERNAME}-"}"
  debuglog "Keeping AGENT_ID ${_prev_id} of the existing install"
fi

# Define the list of capabilities
declare -a CAPABILITIES=(
    "ANSIBLE_RUNNER"
    "BUILD_IMAGE"
    "COMMAND_EXECUTION"
    "DHCP_OOB"
    "ENABLE_METRICS"
    "FILE_TRANSFER"
    "HTTP_REQUEST"
    "INBAND_FILE_TRANSFER"
    "INBAND_HTTP_PROXY"
    "INBAND_WEBMKS"
    "NETCONF"
    "OOB_HTTP_PROXY"
    "SPICE"
    "SSH_COMMAND"
    "SWITCH_SNMP_HEALTH"
    "SWITCH_SUBSCRIPTION"
    "SYSLOG"
    "VNC"
)

# Default values for non-ACAP variables
export ENVVAR_SITE_CONTROLLER_IP="${interface_ip}"
export ENVVAR_DHCP_LISTEN_INTERFACES="${interface_name}"

# Set capability environment variables based on ACAP_ inputs
for CAP in "${CAPABILITIES[@]}"; do
    ACAP_VAR="ACAP_${CAP}"
    ENVVAR="ENVVAR_${CAP}"
    if [[ "${!ACAP_VAR:-0}" = "1" ]]; then
        export "${ENVVAR}=enabled"
        #debuglog "Capability ${YELLOW}${CAP}${nc} enabled via ${ACAP_VAR}" info green
    # else
    #     # Set defaults for specific capabilities if not explicitly enabled
    #     case "$CAP" in
    #         "OOB_HTTP_PROXY"|"FILE_TRANSFER"|"SWITCH_SUBSCRIPTION"|"COMMAND_EXECUTION"|"VNC"|"SYSLOG"|"NETCONF")
    #             export "${ENVVAR}=enabled" # Default enabled
    #             ;;
    #         *)
    #             export "${ENVVAR}=disabled" # Default disabled
    #             ;;
    #     esac
    # #      # Ensure Ansible runner specific vars are disabled if ACAP is not set
    #     if [[ "$CAP" == "ANSIBLE_RUNNER" ]]; then
    #         export "${ENVVAR}=disabled"
    #     fi
    fi
done

# The controller's install one-liner passes these two without the ACAP_ prefix (ENABLE_METRICS=1)
for CAP in ENABLE_METRICS SWITCH_SNMP_HEALTH; do
    case "${!CAP:-}" in
        1|true|enabled) export "ENVVAR_${CAP}=enabled" ;;
    esac
done

# Initialize ansible variables
ansible_runner=""
ms_agent_ansible_runner_mounts=""
ms_agent_ansible_runner_volumes=""

# Conditionally define ansible-runner service and ms-agent mounts
if [[ "${ENVVAR_ANSIBLE_RUNNER:-disabled}" == "enabled" ]]; then
        #debuglog "ANSIBLE_RUNNER capability enabled" info green
        if verlt "$IMAGES_TAG" v7.4.0; then
        ansible_runner="  ansible-runner:
    container_name: ansible-runner
    network_mode: host
    hostname: ansible-runner-${DATACENTERNAME}-${HOSTNAMERANDOM}
    image: ${ANSIBLE_RUNNER_URL}
    restart: always
    environment:
      - TZ=Etc/UTC
      - ANSIBLE_RUNNER=enabled
      - ANSIBLE_RUNNER_HOME=/opt/metalsoft/ansible-jobs
      - ANSIBLE_RUNNER_ARCHIVES_FOLDER=/opt/metalsoft/ansible-archives
    volumes:
      - /opt/metalsoft/ansible-jobs:/opt/metalsoft/ansible-jobs
      - /opt/metalsoft/ansible-archives:/opt/metalsoft/ansible-archives

### pull openshift binaries
# OCP_VERSION=4.20.5
# curl -L \"https://mirror.openshift.com/pub/openshift-v4/clients/ocp/\${OCP_VERSION}/openshift-install-linux-\${OCP_VERSION}.tar.gz\" -o openshift-install.tar.gz && tar xzf openshift-install.tar.gz openshift-install && rm -f openshift-install.tar.gz
# curl -L \"https://mirror.openshift.com/pub/openshift-v4/clients/ocp/\${OCP_VERSION}/openshift-client-linux-\${OCP_VERSION}.tar.gz\" -o openshift-client.tar.gz && tar -xzf openshift-client.tar.gz oc && rm -f openshift-client.tar.gz
# mkdir -p /opt/metalsoft/extensions
# mv {oc,openshift-install} /opt/metalsoft/extensions/
# ls -la /opt/metalsoft/extensions/
### once you have the binaries, uncomment below lines:

      #- /opt/metalsoft/extensions/oc:/usr/local/bin/oc:ro
      #- /opt/metalsoft/extensions/openshift-install:/usr/local/bin/openshift-install:ro
      #- /opt/metalsoft/nfs-storage:/iso
"
        fi
        ms_agent_ansible_runner_mounts="
      - ANSIBLE_RUNNER=enabled
      - ANSIBLE_RUNNER_HOME=/opt/metalsoft/ansible-jobs
      - ANSIBLE_RUNNER_ARCHIVES_FOLDER=/opt/metalsoft/ansible-archives
      - ANSIBLE_RUNNER_RUN_UID=\"1000\"
      - ANSIBLE_RUNNER_RUN_GID=\"1000\"
      - ANSIBLE_RUNNER_EXECUTION_ENV=\${ANSIBLE_RUNNER_EXECUTION_ENV:-registry.metalsoft.dev/ee/ee-default:latest}
      - ANSIBLE_RUNNER_SOCKET_PATH=\${ANSIBLE_RUNNER_SOCKET_PATH:-/var/run/docker.sock}
      - ANSIBLE_RUNNER_HOME_HOST=\${ANSIBLE_RUNNER_HOME_HOST:-/opt/metalsoft/ansible-jobs}
      - ANSIBLE_RUNNER_EXECUTION_CONTAINER_DNS_SERVERS=\"8.8.8.8,1.1.1.1\"
      - ANSIBLE_RUNNER_EXECUTION_CONTAINER_NETWORK_MODE=\"bridge\" # [bridge|host|none]
      #- ANSIBLE_RUNNER_DEBUG_KEEP_CONTAINER=1
"
fi

# ms-agent ansible runner volumes. Present when ANSIBLE_RUNNER enabled, or always for v7.4.0+
# (the runner moved into ms-agent). Socket mount + docker group_add are active only for v7.4.0+
# with ANSIBLE_RUNNER enabled (docker socket access is root-equivalent on the host).
if [[ "${ENVVAR_ANSIBLE_RUNNER:-disabled}" == "enabled" ]] && ! verlt "$IMAGES_TAG" v7.4.0; then
    sock_prefix="- "
    group_add_prefix=""
else
    sock_prefix="#- "
    group_add_prefix="#"
fi
if [[ "${ENVVAR_ANSIBLE_RUNNER:-disabled}" == "enabled" ]] || ! verlt "$IMAGES_TAG" v7.4.0; then
    ms_agent_ansible_runner_volumes="
      - /opt/metalsoft/ansible-jobs:/opt/metalsoft/ansible-jobs
      - /opt/metalsoft/ansible-archives:/opt/metalsoft/ansible-archives
      ${sock_prefix}\${ANSIBLE_RUNNER_SOCKET_PATH:-/var/run/docker.sock}:\${ANSIBLE_RUNNER_SOCKET_PATH:-/var/run/docker.sock}
"
fi

# Initialize sc-image-builder variable
sc_image_builder=""

# Conditionally define sc-image-builder service
    if ! verlt "$IMAGES_TAG" v7.2.0; then
if [[ "${ENVVAR_BUILD_IMAGE:-disabled}" == "enabled" ]] || [[ "${ENVVAR_BUILD_IMAGE:-disabled}" == "1" ]]; then
        sc_image_builder="  sc-image-builder:
    container_name: sc-image-builder
    network_mode: host
    hostname: sc-image-builder-${DATACENTERNAME}-${HOSTNAMERANDOM}
    image: ${SCIMAGEBUILDER_URL}
    restart: always
    extra_hosts:
      - \"ms-agent:127.0.0.1\"
    environment:
      # - LOG_LEVEL=debug
      # - MINIMUM_FREE_DISK_SIZE_GB_TO_START_BUILD=40
      - OS_IMAGES_MOUNT=/iso
      - MAXIMUM_BUILDS_IN_PARALLEL=20
    volumes:
      - /opt/metalsoft/nfs-storage:/iso
"
else
        sc_image_builder="#  sc-image-builder:
#    container_name: sc-image-builder
#    network_mode: host
#    hostname: sc-image-builder-${DATACENTERNAME}-${HOSTNAMERANDOM}
#    image: ${SCIMAGEBUILDER_URL}
#    restart: always
#    extra_hosts:
#      - \"ms-agent:127.0.0.1\"
#    environment:
#      # - LOG_LEVEL=debug
#      # - MINIMUM_FREE_DISK_SIZE_GB_TO_START_BUILD=40
#      - OS_IMAGES_MOUNT=/iso
#      - MAXIMUM_BUILDS_IN_PARALLEL=20
#    volumes:
#      - /opt/metalsoft/nfs-storage:/iso
"
    fi
fi

# Determine NFS service configuration (DEPLOY_NFS=1 to enable, default: enabled)
if [[ "${DEPLOY_NFS:-1}" == "1" ]]; then
  nfs_service="  nfs:
    network_mode: host
    container_name: nfs-server
    image: ${REG_HOST}/sc/nfs-server:3
    restart: unless-stopped
    privileged: true
    environment:
      - NFS_EXPORT_0=/data                *(ro,no_subtree_check)
      #- NFS_EXPORT_1=/data/test-iso       *(ro,no_auth_nlm)
    volumes:
      - /opt/metalsoft/nfs-storage:/data
    ports:
      - 2049:2049
      - 111:111
      - 32765:32765
      - 32767:32767
"
else
  nfs_service="#  nfs:
#    network_mode: host
#    container_name: nfs-server
#    image: ${REG_HOST}/sc/nfs-server:3
#    restart: unless-stopped
#    privileged: true
#    environment:
#      - NFS_EXPORT_0=/data                *(ro,no_subtree_check)
#      #- NFS_EXPORT_1=/data/test-iso       *(ro,no_auth_nlm)
#    volumes:
#      - /opt/metalsoft/nfs-storage:/data
#    ports:
#      - 2049:2049
#      - 111:111
#      - 32765:32765
#      - 32767:32767
"
fi

# --- Metrics (opt-in) -------------------------------------------------------
# ENVVAR_ENABLE_METRICS=enabled (or ACAP_ENABLE_METRICS=1 / ENABLE_METRICS=1) turns on:
#   - the ENABLE_METRICS capability on ms-agent (ENABLE_METRICS=true; the agent only serves
#     Prometheus /metrics on port 9464 when this is set - default false)
#   - if the METRICS_* variables below are set, a vmagent container that scrapes 127.0.0.1:9464 and pushes the samples with
#     Prometheus remote_write (HTTPS + basic auth) to the central Prometheus. Push,
#     because site controllers are usually behind NAT: only outbound connections,
#     like the agent's own tunnel. Buffers up to 32MB in memory (tmpfs) while the receiver is
#     unreachable and replays afterwards. The buffer is empty on every container start: after an
#     outage longer than the receiver's out-of-order window (6h) the oldest buffered block is
#     rejected with "too old sample" (HTTP 500 on Prometheus v2.39), which vmagent retries forever
#     and which would block everything queued behind it.
# Required for the vmagent pusher (without them only the agent's /metrics endpoint is turned on):
#   METRICS_REMOTE_WRITE_URL       e.g. https://grafana.example.com/api/v1/write
#   METRICS_REMOTE_WRITE_USERNAME  basic-auth user created on the receiver
#   METRICS_REMOTE_WRITE_PASSWORD  its password (stored in /opt/metalsoft/agents/vmagent/secrets, mode 0600)
#   METRICS_GC_NAMESPACE           k8s namespace of the Global Controller env this SC belongs to (e.g. qa03-metalcloud);
#                                  becomes the `namespace` label so the SC shows up under its env in the MS Grafana dashboards
# Optional:
#   METRICS_SC_NAME                `pod`/`instance`/`site_controller` label (default: <datacenter>-<ip with dashes>, stable across re-runs)
#   METRICS_SCRAPE_INTERVAL        default 30s
#   METRICS_REMOTE_WRITE_CA_FILE   CA bundle for the receiver, path inside the container (/etc/ssl/certs of the host is
#                                  mounted there; default: system trust store, which already holds the MetalSoft CA)
#   METRICS_REMOTE_WRITE_INSECURE=1  skip TLS verification of the receiver (not recommended)
#   VMAGENT_URL                    image override
metrics_service=""
# The agent parses ENABLE_METRICS with strconv.ParseBool, so it gets true/false, not enabled/disabled.
ms_agent_enable_metrics=false
metrics_push=0
if [[ "${ENVVAR_ENABLE_METRICS:-disabled}" == "enabled" ]] || [[ "${ENVVAR_ENABLE_METRICS:-disabled}" == "1" ]]; then
  export ENVVAR_ENABLE_METRICS=enabled
  ms_agent_enable_metrics=true
  metrics_missing=""
  metrics_set=0
  for metrics_var in METRICS_REMOTE_WRITE_URL METRICS_REMOTE_WRITE_USERNAME METRICS_REMOTE_WRITE_PASSWORD METRICS_GC_NAMESPACE; do
    if [ -n "${!metrics_var}" ]; then metrics_set=1; else metrics_missing+=" ${metrics_var}"; fi
  done
  # all set: vmagent; none set (the controller one-liner): only ENABLE_METRICS=true on ms-agent, silently
  if [ -z "$metrics_missing" ]; then
    metrics_push=1
  elif [ "$metrics_set" = "1" ]; then
    debuglog "vmagent pusher not deployed, not set:${metrics_missing}" info yellow
  fi
fi
if [ "$metrics_push" = "1" ]; then
  METRICS_SC_NAME="${METRICS_SC_NAME:-${DATACENTERNAME}-$(echo "$interface_ip" | sed 's/[.:][.:]*/-/g')}"
  METRICS_SCRAPE_INTERVAL="${METRICS_SCRAPE_INTERVAL:-30s}"
  debuglog "Metrics enabled: vmagent pushes ms-agent metrics as pod=${METRICS_SC_NAME} namespace=${METRICS_GC_NAMESPACE} to ${METRICS_REMOTE_WRITE_URL}"
  mkdir -p /opt/metalsoft/agents/vmagent/secrets
  # on-disk queue of older deployments, replaced by the tmpfs below
  rm -rf /opt/metalsoft/agents/vmagent/data
  (umask 077
   printf '%s' "${METRICS_REMOTE_WRITE_USERNAME}" > /opt/metalsoft/agents/vmagent/secrets/username
   printf '%s' "${METRICS_REMOTE_WRITE_PASSWORD}" > /opt/metalsoft/agents/vmagent/secrets/password)
  chmod 600 /opt/metalsoft/agents/vmagent/secrets/username /opt/metalsoft/agents/vmagent/secrets/password
  cat > /opt/metalsoft/agents/vmagent/scrape.yml <<ENDD
# generated by deploy-agents.sh - edits are overwritten on the next run
global:
  scrape_interval: ${METRICS_SCRAPE_INTERVAL}
  # make the site controller look like one more app pod of its GC environment
  external_labels:
    namespace: "${METRICS_GC_NAMESPACE}"
    pod: "${METRICS_SC_NAME}"
    site_controller: "${METRICS_SC_NAME}"
    datacenter: "${DATACENTERNAME}"
    agent_id: "${DATACENTERNAME}-${HOSTNAMERANDOM}"
    endpoint: metrics

scrape_configs:
  - job_name: site-controller
    static_configs:
      - targets: ["127.0.0.1:9464"]
    relabel_configs:
      - target_label: instance
        replacement: "${METRICS_SC_NAME}"
ENDD
  metrics_tls_line=""
  if [[ "${METRICS_REMOTE_WRITE_INSECURE:-0}" == "1" ]]; then
    metrics_tls_line="      - -remoteWrite.tlsInsecureSkipVerify=true"
  elif [ -n "${METRICS_REMOTE_WRITE_CA_FILE}" ]; then
    metrics_tls_line="      - -remoteWrite.tlsCAFile=${METRICS_REMOTE_WRITE_CA_FILE}"
  fi
  metrics_service="  vmagent:
    container_name: vmagent
    network_mode: host
    hostname: vmagent-${DATACENTERNAME}-${HOSTNAMERANDOM}
    image: ${VMAGENT_URL}
    restart: always
    mem_limit: 256m
    environment:
      - TZ=Etc/UTC
    command:
      - -promscrape.config=/etc/vmagent/scrape.yml
      - -promscrape.configCheckInterval=1m
      - -httpListenAddr=127.0.0.1:8429
      - -remoteWrite.url=${METRICS_REMOTE_WRITE_URL}
      - -remoteWrite.basicAuth.usernameFile=/etc/vmagent/secrets/username
      - -remoteWrite.basicAuth.passwordFile=/etc/vmagent/secrets/password
${metrics_tls_line}
      # in-memory buffer (tmpfs) while the receiver is unreachable: empty on every container start,
      # so a block too old for the receiver cannot block the queue after a long outage
      - -remoteWrite.tmpDataPath=/vmagent-data
      - -remoteWrite.maxDiskUsagePerURL=32MB
      # receiver is Prometheus: plain remote_write protocol, one queue so replayed samples stay in order
      - -remoteWrite.forcePromProto=true
      - -remoteWrite.queues=1
    # counts against mem_limit; kept above maxDiskUsagePerURL
    tmpfs:
      - /vmagent-data:size=48m
    volumes:
      - /opt/metalsoft/agents/vmagent/scrape.yml:/etc/vmagent/scrape.yml:ro
      - /opt/metalsoft/agents/vmagent/secrets:/etc/vmagent/secrets:ro
      - /etc/ssl/certs:/etc/ssl/certs:ro
"
else
  metrics_service="#  vmagent: metrics pusher - disabled. Re-run with ENABLE_METRICS=1 plus
#    METRICS_REMOTE_WRITE_URL, METRICS_REMOTE_WRITE_USERNAME, METRICS_REMOTE_WRITE_PASSWORD, METRICS_GC_NAMESPACE
#    (see the Metrics section of deploy-agents.sh).
"
fi

inband_dc="  ms-agent:
    container_name: ms-agent
    network_mode: host
    hostname: ms-agent-${DATACENTERNAME}-${HOSTNAMERANDOM}
    image: ${MSAGENT_URL}
    restart: always
    cap_add: [NET_BIND_SERVICE, NET_ADMIN]
    ### group_add: active only for v7.4.0+ with ANSIBLE_RUNNER enabled - gives ms-agent (appuser) access to the docker socket (root-equivalent on host)
${group_add_prefix}    group_add: [\"\${DOCKER_GID:-${DOCKER_GID}}\"]
#    security_opt: [\"no-new-privileges:true\"]
    environment:
      # - HTTP_PROXY=http://proxy_ip_here:3128
      # - HTTPS_PROXY=http://proxy_ip_here:3128
      # - NO_PROXY=localhost,127.0.0.1,::1,172.16.0.0/12,192.168.0.0/16
      # - HTTP_PORT=80
      # - HTTPS_PORT=443
      # - TLS_PEM_FILE=/etc/ssl/certs/ssl-cert.pem
      # - GC_NOVERIFY_SSL=true
      # - FILE_SERVE_TIMEOUT=30 #minutes
      - TZ=Etc/UTC
      - AGENT_ID=${DATACENTERNAME}-${HOSTNAMERANDOM}
      - AGENT_SECRET=${MS_TUNNEL_SECRET}
      - DATACENTER_ID=${DATACENTERNAME}
      - MONITORING_SERVICE_PORT=${MONITORING_SERVICE_PORT:-80}
      - LOG_LEVEL=debug
      - CONTROLLER_WS_URI=wss://${SSL_HOSTNAME}/tunnel-ctrl
      - CONTROLLER_REMOTE_CONSOLE_URI=wss://${SSL_HOSTNAME}/agent-remote-console
      - OS_IMAGES_MOUNT=/iso
      - NFS_HOST=${NFSIP}:/data
      - SITE_CONTROLLER_IP=${ENVVAR_SITE_CONTROLLER_IP}
      # - SITE_CONTROLLER_SYSLOG_SERVER_IP=
      # - SITE_CONTROLLER_SYSLOG_SWITCH_IP=
      ### DHCP_LISTEN_INTERFACES if not set here, is auto-discovered by code
      # - DHCP_LISTEN_INTERFACES=${ENVVAR_DHCP_LISTEN_INTERFACES}
      # - DHCP_DNS_SERVERS=\"1.1.1.1,8.8.8.8\"
      # - MAX_SWITCH_SNMP_HEALTH_SUBSCRIPTIONS=2000
      # - MAX_CONCURRENT_SWITCH_SNMP_HEALTH_SUBSCRIPTIONS=50
      # - POLL_INTERVAL_SECONDS_SWITCH_SNMP_HEALTH_SUBSCRIPTIONS=60

      ## Capabilities:
      - BUILD_IMAGE=${ENVVAR_BUILD_IMAGE:-disabled}
      - COMMAND_EXECUTION=${ENVVAR_COMMAND_EXECUTION:-disabled}
      - DHCP_OOB=${ENVVAR_DHCP_OOB:-disabled}
      ## ENABLE_METRICS is a boolean in the agent (strconv.ParseBool: true/false/1/0), unlike the other capabilities
      - ENABLE_METRICS=${ms_agent_enable_metrics:-false}
      - FILE_TRANSFER=${ENVVAR_FILE_TRANSFER:-disabled}
      - HTTP_REQUEST=${ENVVAR_HTTP_REQUEST:-disabled}
      - INBAND_FILE_TRANSFER=${ENVVAR_INBAND_FILE_TRANSFER:-disabled}
      - INBAND_HTTP_PROXY=${ENVVAR_INBAND_HTTP_PROXY:-disabled}
      - INBAND_WEBMKS=${ENVVAR_INBAND_WEBMKS:-disabled}
      - NETCONF=${ENVVAR_NETCONF:-disabled}
      - OOB_HTTP_PROXY=${ENVVAR_OOB_HTTP_PROXY:-disabled}
      - SPICE=${ENVVAR_SPICE:-disabled}
      - SSH_COMMAND=${ENVVAR_SSH_COMMAND:-disabled}
      - SWITCH_SNMP_HEALTH=${ENVVAR_SWITCH_SNMP_HEALTH:-enabled}
      - SWITCH_SUBSCRIPTION=${ENVVAR_SWITCH_SUBSCRIPTION:-disabled}
      - SYSLOG=${ENVVAR_SYSLOG:-disabled}
      - VNC=${ENVVAR_VNC:-disabled}
$ms_agent_ansible_runner_mounts
    volumes:
      - /opt/metalsoft/nfs-storage:/iso
      - ${ms_agent_ssl_os_ca_path}:/etc/ssl/certs
$ms_agent_ansible_runner_volumes
      # - /etc/hosts:/etc/hosts:ro
      # - /opt/metalsoft/agents/ssl-cert.pem:/etc/ssl/certs/ssl-cert.pem
${nfs_service}"
other_services="
#  pdns-auth-recursor:
#    container_name: pdns-auth-recursor
#    network_mode: host
#    hostname: pdns-auth-recursor
#    image: ${REG_HOST}/sc/sc-pdns-auth-recursor:main
#    restart: always
#    environment:
#      - TZ=Etc/UTC
#    volumes:
#      - /opt/metalsoft/pdns:/appdata
"
debuglog "Creating /opt/metalsoft/agents/docker-compose.yaml"
echo "TAG=${IMAGES_TAG}" > /opt/metalsoft/agents/.env
unset TAG # an inherited TAG would override .env in compose
cat > /opt/metalsoft/agents/docker-compose.yaml <<ENDD
services:
$inband_dc
$ansible_runner
$sc_image_builder
$metrics_service
$other_services
ENDD

    test -n "${CLI_MS_TUNNEL_SECRET}" && sed -i "s/\(\s\+\- AGENT_SECRET=\).*/\1${CLI_MS_TUNNEL_SECRET}/g" /opt/metalsoft/agents/docker-compose.yaml
    test -n "${CLI_DATACENTERNAME}" && sed -i "s/\(\s\+\- DATACENTER_ID=\).*/\1${CLI_DATACENTERNAME}/g" /opt/metalsoft/agents/docker-compose.yaml

# Per-SC values also go to .env, read back from the compose above so CLI overrides are included.
# The systemd-managed SC (sc-ctl.sh) reads them (GC auth, registry, tag), and compose files that use ${VAR} get the same values.
chmod 0600 /opt/metalsoft/agents/docker-compose.yaml # holds AGENT_SECRET
compose_value() { grep -Po "^\s+- $1=\K.*" /opt/metalsoft/agents/docker-compose.yaml 2>/dev/null | head -1; }
(
  umask 077
  {
    echo "TAG=${IMAGES_TAG}"
    echo "REG_HOST=${REG_HOST}"
    echo "GC_HOSTNAME=${SSL_HOSTNAME}"
    for k in AGENT_ID AGENT_SECRET DATACENTER_ID SITE_CONTROLLER_IP NFS_HOST LOG_LEVEL \
             BUILD_IMAGE COMMAND_EXECUTION DHCP_OOB ENABLE_METRICS FILE_TRANSFER HTTP_REQUEST INBAND_FILE_TRANSFER \
             INBAND_HTTP_PROXY INBAND_WEBMKS NETCONF OOB_HTTP_PROXY SPICE SSH_COMMAND SWITCH_SNMP_HEALTH \
             SWITCH_SUBSCRIPTION SYSLOG VNC; do
      v="$(compose_value "$k")"
      # single quotes keep compose from expanding a '$' inside the value (e.g. in a secret)
      if [[ $v == *'$'* && $v != *"'"* ]]; then echo "$k='$v'"; elif [ -n "$v" ]; then echo "$k=$v"; fi
    done
  } > /opt/metalsoft/agents/.env
)
chmod 0600 /opt/metalsoft/agents/.env # '>' keeps the mode of the file created above with the default umask

if [ "$SC_SYSTEMD" = 1 ]; then
  debuglog "SC_SYSTEMD=1: compose takes per-SC values from .env; systemd restarts ms-agent"
  _c=/opt/metalsoft/agents/docker-compose.yaml
  # every key written to .env is referenced, so the GC (bundles) and the OVA network hook change it in one place
  for k in $(sed -n 's/^\([A-Z_][A-Z0-9_]*\)=.*/\1/p' /opt/metalsoft/agents/.env); do
    sed -i "s|^\(\s\+- $k=\).*|\1\${$k}|" "$_c"
  done
  sed -i "s|^\(\s\+image: \)${REG_HOST}/|\1\${REG_HOST}/|" "$_c"
  # ms-agent: the unit restarts it when it exits (also to apply an upgrade); the entrypoint makes the agent PID 1
  # (images before the Dockerfile change still restart it in a loop inside the container)
  sed -i '/^  ms-agent:$/,/^  [^ #]/ s|^    restart: always$|    restart: "no"\n    entrypoint: ["/bin/sh", "-c", "umask 022; exec /usr/bin/agent"]|' "$_c"
  # SELinux (RHEL + podman): relabel the shared data dir for containers; ignored without SELinux
  sed -i 's#^\(\s\+- /opt/metalsoft/nfs-storage:/\(iso\|data\)\)$#\1:z#' "$_c"
fi


dcname="$(grep -Po 'DATACENTER_ID=\K.*' /opt/metalsoft/agents/docker-compose.yaml 2>/dev/null|head -1)" && test -n "$dcname" && if ! grep -qP "^PS1=.+SC: .+" "$HOME/.bashrc";then echo "PS1='\\[\\e[1;43m\\]SC: $dcname \\[\\e[00m\\]\\[\\e[1;33m\\]\\h\\[\\e[1;34m\\] \\W\\[\\e[1;34m\\] \\$\\[\\e[m\\] '" >> "$HOME/.bashrc" && source "$HOME/.bashrc";fi

if ! command -v "$DOCKERBIN" >/dev/null 2>&1; then
  echo -e "${lightred}Error: $DOCKERBIN command not found. Please ensure $DOCKERBIN is installed.${nc}" >&2
  exit 1
fi

debuglog "Starting $DOCKERBIN containers"
if [ "$DOCKERBIN" == "docker" ];then
  systemctl enable -q --now docker.service
  until docker ps &>/dev/null;do sleep 1;echo -ne "[-] Waiting for docker service to start.. \033[0K\r";done #&& echo
  else
  systemctl enable -q --now podman
  systemctl enable -q --now podman.socket
  if [ "$SC_SYSTEMD" = 1 ]; then
    systemctl disable -q --now podman-compose-agents.service 2>/dev/null || true
  else
  cat > /etc/systemd/system/podman-compose-agents.service << EOF
[Unit]
Description=Podman-compose-agents.service
Documentation=man:podman-generate-systemd(1)
Wants=network-online.target
After=network-online.target

[Service]
WorkingDirectory=/opt/metalsoft/agents
#Environment=PODMAN_SYSTEMD_UNIT=%n
Restart=on-failure
TimeoutStopSec=70
ExecStart=/usr/local/bin/podman-compose -f /opt/metalsoft/agents/docker-compose.yaml up
ExecStop=/usr/local/bin/podman-compose -f /opt/metalsoft/agents/docker-compose.yaml down
Type=simple

[Install]
WantedBy=default.target

EOF
    systemctl daemon-reload
    systemctl enable -q --now podman-compose-agents.service
  fi
  # until ${DOCKERBIN}-compose ps &>/dev/null;do sleep 1;echo -ne "[-] Waiting for $DOCKERBIN service to start.. \033[0K\r";done && echo
fi

mkdir -p "${HOME}/.docker"
if [ -n "${REGISTRY_LOGIN}" ]; then
    # Check if REGISTRY_LOGIN is valid base64
    if echo "${REGISTRY_LOGIN}" | base64 -d &>/dev/null; then
        echo "{\"auths\":{\"${REG_HOST}\":{\"auth\":\"${REGISTRY_LOGIN}\"}}}" > "${HOME}/.docker/config.json"
    else
        debuglog "Warning: REGISTRY_LOGIN is not valid base64 format. Will NOT save it to ${HOME}/.docker/config.json" fail
    fi
fi

PULL_SUCCESS=0
if [ -z "$REG_HOST_CONN_FAILED" ];then
debuglog "Login to $DOCKERBIN with Metalsoft provided credentials for ${REG_HOST}:"
while ! $DOCKERBIN login "${REG_HOST}"; do
  debuglog "Lets try again: $DOCKERBIN login ${REG_HOST}:"
  sleep 1
done


if [ "$found_os" == "debian" ];then
  debuglog "Stop and disable host systemd-resolved.service, which will be replaced by agent's DNS $DOCKERBIN container"
  systemctl disable --now systemd-resolved.service 2>/dev/null || true
  systemctl disable --now rpcbind 2>/dev/null || true
  systemctl disable --now rpcbind.socket 2>/dev/null || true
  systemctl daemon-reload

  debuglog "Add DNS resolvers to /etc/resolv.conf"
  test -L /etc/resolv.conf && \rm -f /etc/resolv.conf && touch /etc/resolv.conf && RESOLVCONFCHANGED="YES"
  find /etc/netplan -type f -iname "*.yaml" | while read -r netplan_file; do
    nameservers=$(yq e '.network.ethernets[].nameservers.addresses[]' "$netplan_file" 2>/dev/null)
    # redundancy, also the only dependenscy that needs jq and yamltojson
    test -z "$nameservers" && nameservers="$(yamltojson "$netplan_file" 2>/dev/null | jq .network.ethernets 2>/dev/null | jq -r '.[].nameservers | .addresses' 2>/dev/null | jq -sr 'flatten(1) | join(" ")' 2>/dev/null)"
    for nameserver in $nameservers; do
      debuglog "netplan nameserver ${yellow}$nameserver${nc}"
      if [[ "$nameserver" != "$(grep "$nameserver" /etc/resolv.conf | cut -d" " -f2)" ]];then
        echo "nameserver $nameserver" >> /etc/resolv.conf
        RESOLVCONFCHANGED="YES"
      fi
    done
  done
else #if rhel
  test -L /etc/resolv.conf && \rm -f /etc/resolv.conf && touch /etc/resolv.conf && RESOLVCONFCHANGED="YES"
  nameservers="$(nmcli d show "$interface_name" 2>/dev/null |grep IP4.DNS|awk '{print $2}'|xargs)"
  test -n "$nameservers" && for nameserver in $nameservers; do
    debuglog "nmcli nameserver ${yellow}$nameserver${nc}"
    if [[ $nameserver != $(grep "$nameserver" /etc/resolv.conf | cut -d" " -f2) ]];then
      echo "nameserver $nameserver" >> /etc/resolv.conf
      RESOLVCONFCHANGED="YES"
    fi
    # setenforce 0 && sed -i 's/^SELINUX=enforcing$/SELINUX=permissive/' /etc/selinux/config
  done
  debuglog "Stop and disable rpcbind service/socket, which will be replaced by agent's nfs-server container"
  systemctl disable --now rpcbind 2>/dev/null || true
  systemctl disable --now rpcbind.socket 2>/dev/null || true
  systemctl daemon-reload
fi


cd /opt/metalsoft/agents || { echo "Error: Failed to change directory to /opt/metalsoft/agents" >&2; exit 1; }
debuglog "pulling latest images.."
if [ "$DOCKERBIN" == "docker" ];then
  $DOCKERBIN compose pull && PULL_SUCCESS=1
else
  ${DOCKERBIN}-compose pull && PULL_SUCCESS=1
fi

# SC_SYSTEMD=1: the unit takes over even if the pull above failed (it retries the pull and falls back to local images);
# leaving the old containers on a compose file already rewritten for the unit would not restart ms-agent.
if [ "$PULL_SUCCESS" -eq 1 ] || [ "$SC_SYSTEMD" = 1 ]; then
  # Only the SC's own containers: this compose project (old services included via --remove-orphans),
  # plus any container holding one of the compose file's container_name values. Other containers on the host stay.
  debuglog "stopping SC $DOCKERBIN containers.." info lightred
  if [ "$DOCKERBIN" == "docker" ];then
    $DOCKERBIN compose down --remove-orphans >/dev/null 2>&1 || true
  else
    ${DOCKERBIN}-compose down --remove-orphans >/dev/null 2>&1 || true
  fi
  for cname in $(grep -Po '^\s+container_name:\s*\K\S+' /opt/metalsoft/agents/docker-compose.yaml); do
    $DOCKERBIN rm -f "$cname" >/dev/null 2>&1 || true
  done

  if [ "$SC_SYSTEMD" = 1 ]; then
    install_sc_systemd
    debuglog "starting metalsoft-sc.service (journalctl -t metalsoft-sc -f)"
    systemctl enable -q metalsoft-sc.service && systemctl restart metalsoft-sc.service
  else
  debuglog "starting containers with updated images.."
  if [ "$DOCKERBIN" == "docker" ];then
    $DOCKERBIN compose up -d --remove-orphans
  else
    ${DOCKERBIN}-compose up -d
  fi
  fi
else
  debuglog "Image pull failed, skipping container restart to avoid downtime" fail
fi

else
  debuglog "Registry connection to ${REG_HOST} failed, skipping docker login and image pull" info yellow
fi

if [ -f /etc/ssh/ms_banner ];then
  debuglog "update /etc/ssh/ms_banner"
  sed -i '/^AgentIP:/d;/^Controller:/d' /etc/ssh/ms_banner # renamed to "SC IP:" / "GC:"
  if grep -q '^SC IP:' /etc/ssh/ms_banner;then sed -i "/^SC IP:.*/c SC IP: $interface_ip" /etc/ssh/ms_banner;else echo "SC IP: $interface_ip" >> /etc/ssh/ms_banner;fi
  if grep -q '^GC:' /etc/ssh/ms_banner;then sed -i "/^GC:.*/c GC: https://${SSL_HOSTNAME}" /etc/ssh/ms_banner;else echo "GC: https://${SSL_HOSTNAME}" >> /etc/ssh/ms_banner;fi
  dcname="$(grep -Po 'DATACENTER_ID=\K.*' /opt/metalsoft/agents/docker-compose.yaml|head -1)" && if grep -q '^Datacenter:' /etc/ssh/ms_banner;then sed -i "/^Datacenter:.*/c Datacenter: $dcname" /etc/ssh/ms_banner;else echo "Datacenter: $dcname" >> /etc/ssh/ms_banner;fi
fi



if ! grep -q nameserver /etc/resolv.conf;then
  echo -e "nameserver 1.1.1.1\nnameserver 8.8.8.8" > /etc/resolv.conf
  RESOLVCONFCHANGED="YES"
fi

if [[ -n ${RESOLVCONFCHANGED} ]];then
  debuglog "Resolv.conf changed, restarting $DOCKERBIN containers"
  cd /opt/metalsoft/agents || exit 1
  if [ "$SC_SYSTEMD" = 1 ]; then
    systemctl try-restart metalsoft-sc.service
  elif [ "$DOCKERBIN" == "docker" ];then
    $DOCKERBIN compose down
    $DOCKERBIN compose up -d --remove-orphans
  else
    ${DOCKERBIN}-compose down
    ${DOCKERBIN}-compose up -d
  fi
  cd - || exit 1
fi


debuglog "Pulling discovery ISO"
test ! -f /opt/metalsoft/nfs-storage/BDK.iso && curl $curl_s_proxy -#L -o /opt/metalsoft/nfs-storage/BDK.iso https://repo.metalsoft.io/.tftp/BDK-Rocky-9-x86_64.iso

if [ "$PULL_SUCCESS" -eq 1 ]; then
sleep 2
$DOCKERBIN ps
fi
sleep 2
$DOCKERBIN ps

debuglog "[ ${SECONDS} sec ] All done. To check containers, use: $DOCKERBIN ps" success
