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

debuglog "OS: ${yellow}$NAME $VERSION_ID${nc} / ${yellow}$os_packager${nc} for ${yellow}$found_os${nc} / ${lightgreen}$DOCKERBIN${nc} / whoami: ${pink}$(whoami)${nc}"
if [ "$found_os" == "debian" ];then
  export LC_ALL=C
  export DEBIAN_FRONTEND=noninteractive
  export APT_LISTCHANGES_FRONTEND=none

  command -v curl  > /dev/null && command -v update-ca-certificates > /dev/null && command -v jq > /dev/null && command -v ip > /dev/null || { debuglog "Installing required packages" && \
    $os_packager update -qq && \
    $os_packager -y install curl ca-certificates net-tools jq dnsutils iproute2 gzip >/dev/null || debuglog "Error installing packages"; }
    else # if rhel
      command -v curl  > /dev/null && command -v update-ca-trust > /dev/null && command -v jq > /dev/null && command -v netstat > /dev/null || { debuglog "Installing required packages" && \
        $os_packager -qy install curl ca-certificates bind-utils iproute jq nmap-ncat wget net-tools gzip >/dev/null || debuglog "Error installing packages" fail; }
fi

debuglog "Creating folders"
mkdir -p /opt/metalsoft/agents /opt/metalsoft/containerd /opt/metalsoft/nfs-storage/buildImageRequest /opt/metalsoft/ansible-jobs /opt/metalsoft/ansible-archives /opt/metalsoft/pdns || { echo "ERROR: unable to create folders in /opt/"; exit 3; }
chown -R 1000:1000 /opt/metalsoft/ansible-jobs /opt/metalsoft/ansible-archives /opt/metalsoft/nfs-storage
if ! grep -q '^alias a=' /root/.bashrc;then echo "alias a='cd /opt/metalsoft/agents'" >> /root/.bashrc || true;fi

REG_HOST=${REGISTRY_HOST:-"registry.metalsoft.dev"}
IMAGES_TAGENV='${TAG}'
MSAGENT_URL="${REG_HOST}/sc/ms-agent:${IMAGES_TAGENV}"
ANSIBLE_RUNNER_URL="${REG_HOST}/sc/sc-ansible-playbook-runner:${IMAGES_TAGENV}"
SCIMAGEBUILDER_URL="${REG_HOST}/sc/sc-image-builder:${IMAGES_TAGENV}"

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
test -f /opt/metalsoft/agents/docker-compose.yaml && _nfsip="$(grep -Po 'NFS_HOST=\K[^\:]*' /opt/metalsoft/agents/docker-compose.yaml)" && test -n "$_nfsip" && if [[ $_nfsip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]];then NFSIP="$_nfsip";fi

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

backupPrefix="backup-$(date +"%Y%m%d%H%M%S")"
# Create backup of config files if they exist
for file in docker-compose.yaml ssl-cert.pem; do
  if [ -f "/opt/metalsoft/agents/$file" ]; then
    cp "/opt/metalsoft/agents/$file" "/opt/metalsoft/agents/${backupPrefix}-${file}.bak"
  fi
done

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

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
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

# Define the list of capabilities
declare -a CAPABILITIES=(
    "ANSIBLE_RUNNER"
    "BUILD_IMAGE"
    "COMMAND_EXECUTION"
    "DHCP_OOB"
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
$other_services
ENDD

    test -n "${CLI_MS_TUNNEL_SECRET}" && sed -i "s/\(\s\+\- AGENT_SECRET=\).*/\1${CLI_MS_TUNNEL_SECRET}/g" /opt/metalsoft/agents/docker-compose.yaml
    test -n "${CLI_DATACENTERNAME}" && sed -i "s/\(\s\+\- DATACENTER_ID=\).*/\1${CLI_DATACENTERNAME}/g" /opt/metalsoft/agents/docker-compose.yaml


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

if [ "$PULL_SUCCESS" -eq 1 ]; then
  debuglog "stopping any running $DOCKERBIN containers.." info lightred
  $DOCKERBIN ps -qa|xargs -i bash -c "$DOCKERBIN stop {} && $DOCKERBIN rm {}" >/dev/null

  debuglog "starting containers with updated images.."
  if [ "$DOCKERBIN" == "docker" ];then
    $DOCKERBIN compose up -d --remove-orphans
  else
    ${DOCKERBIN}-compose up -d
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
  if [ "$DOCKERBIN" == "docker" ];then
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
