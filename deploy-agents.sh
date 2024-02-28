#!/bin/bash
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

function parse_yaml {
   local prefix=$2
   local s='[[:space:]]*' w='[a-zA-Z0-9_]*' fs=$(echo @|tr @ '\034')
   sed -ne "s|^\($s\):|\1|" \
        -e "s|^\($s\)\($w\)$s:$s[\"']\(.*\)[\"']$s\$|\1$fs\2$fs\3|p" \
        -e "s|^\($s\)\($w\)$s:$s\(.*\)$s\$|\1$fs\2$fs\3|p"  $1 |
   awk -F$fs '{
      indent = length($1)/2;
      vname[indent] = $2;
      for (i in vname) {if (i > indent) {delete vname[i]}}
      if (length($3) > 0) {
         vn=""; for (i=0; i<indent; i++) {vn=(vn)(vname[i])("_")}
         printf("%s%s%s=\"%s\"\n", "'$prefix'",vn, $2, $3);
      }
   }'
}

debuglog "whoami: $(whoami)" bold pink
export LC_ALL=C
export DEBIAN_FRONTEND=noninteractive
export APT_LISTCHANGES_FRONTEND=none

if [ -n "$DOCKERENV" ];then
  IMAGES_TAG_SAVED="$IMAGES_TAG"
  IMAGES_TAG='${TAG}'
  DCAGENTS_URL="registry.metalsoft.dev/datacenter-agents-compiled/datacenter-agents-compiled-v2:${IMAGES_TAG}"
  JUNOSDRIVER_URL="registry.metalsoft.dev/datacenter-agents-compiled/junos-driver:${IMAGES_TAG}"
  MSAGENT_URL="registry.metalsoft.dev/datacenter-agents-compiled/ms-agent:${IMAGES_TAG}"
else
  test -z "$IMAGES_TAG" && IMAGES_TAG='v6.0.4'
  test -z "$DCAGENTS_URL" && DCAGENTS_URL="registry.metalsoft.dev/datacenter-agents-compiled/datacenter-agents-compiled-v2:${IMAGES_TAG}"
  test -z "$JUNOSDRIVER_URL" && JUNOSDRIVER_URL="registry.metalsoft.dev/datacenter-agents-compiled/junos-driver:${IMAGES_TAG}"
  test -z "$MSAGENT_URL" && MSAGENT_URL="registry.metalsoft.dev/datacenter-agents-compiled/ms-agent:${IMAGES_TAG}"
fi

test -z "$MS_TUNNEL_SECRET" && MS_TUNNEL_SECRET='default'

# Env vars set via CLI:
CLI_DCCONF="$DCCONF"
CLI_DATACENTERNAME="$DATACENTERNAME"

MAINIP="$(hostname -I 2>/dev/null | awk '{print $1}')"
test -z "$MAINIP" && MAINIP="$(ip r get 1|head -1|awk '{print $7}')"
test -z "$SSL_HOSTNAME" && SSL_HOSTNAME="$(echo "$DCCONF"|cut -d/ -f3)"

function testOS
{
  echo
  debuglog "testing OS version"
  if ! grep -q "Ubuntu 2" /etc/issue; then
    echo
    echo "This script is only compatible with Ubuntu 20+ Operating system"
    echo "and will not run on any other OS"
    echo
    exit 2
  fi
}

function nc_check_remote_conn {

  ip=$1
  port=$2
  protocol=${3:-tcp}
  comment="$4 "
  test "$protocol" == 'icmp' && port=icmp

  command -v curl  > /dev/null && command -v update-ca-certificates > /dev/null && command -v dig > /dev/null && command -v jq > /dev/null || { debuglog "Installing required packages" && \
    apt-get update -qq && \
    apt-get -y install curl ca-certificates net-tools jq dnsutils >/dev/null; }

  echo -en "Check connection from ${bold}${MAINIP}${nc} to ${comment}${orange}$ip:$port${nc}: "

  if [[ ! $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    ip="$(dig +short "$ip"|grep -Po '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' |xargs)"
  fi
  for ip in $ip;do

    if [ "$protocol" == "tcp" ];then
      nc -nzw 5 "$ip" "$port" >/dev/null 2>&1 && echo -e "${lightgreen}success${nc}" || echo -e "${lightred}failure${nc}"
    elif [ "$protocol" == "icmp" ];then
      ping -c2 "$ip" >/dev/null 2>&1 && echo -e "${lightgreen}success${nc}" || echo -e "${lightred}failure${nc}"
    else
      nc -nzuw 5 "$ip" "$port" >/dev/null 2>&1 && echo -e "${lightgreen}success${nc}" || echo -e "${lightred}failure${nc}"
    fi
  done
}

nc_check_remote_conn repo.metalsoft.io 80 tcp
nc_check_remote_conn registry.metalsoft.dev 443 tcp
test -n "$SSL_HOSTNAME" && nc_check_remote_conn "${SSL_HOSTNAME}" 443 tcp
test -n "$SSL_HOSTNAME" && nc_check_remote_conn "${SSL_HOSTNAME}" 0 icmp

function manageSSL
{
  test -n "${SSL_PULL_URL}" && curl -skL --connect-timeout 20 "${SSL_PULL_URL}" |tee /root/agents-ssl.pem.tmp && openssl x509 -in /root/agents-ssl.pem.tmp -text -nocert|grep -q 'Not Before:' && mv /root/agents-ssl.pem.tmp /root/agents-ssl.pem || { rm -f /root/agents-ssl.pem.tmp; echo "Error pulling certificate"; }
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
  elif [[ "${NONINTERACTIVE_MODE}" == 1 ]];then
    echo "Error: You are in noninteractive mode, but have not specified value for SSL_PULL_URL";
    exit 1
  else
    echo Error: no valid path provided
    return 1
  fi
}

testOS

test ! -f /usr/local/share/ca-certificates/metalsoft_ca.crt && \
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
test ! -f /usr/local/share/ca-certificates/metalsoft_ca.crt && wget -q https://repo.metalsoft.io/.tftp/metalsoft_ca.crt -O /usr/local/share/ca-certificates/metalsoft_ca.crt
test ! -f /etc/ssl/certs/metalsoft_ca.crt && cp /usr/local/share/ca-certificates/metalsoft_ca.crt /etc/ssl/certs/ && update-ca-certificates

debuglog "Checking for other custom CAs"
if [[ -n "$CUSTOM_CA" ]]; then
  echo ${CUSTOM_CA_CERT} | base64 --decode > /usr/local/share/ca-certificates/${CUSTOM_CA}
  echo ${CUSTOM_CA_CERT} | base64 --decode > /etc/ssl/certs/${CUSTOM_CA}
  update-ca-certificates
fi

debuglog "Creating folders"
mkdir -p /opt/metalsoft/BSIAgentsVolume /opt/metalsoft/logs /opt/metalsoft/logs_agents /opt/metalsoft/agents /opt/metalsoft/containerd /opt/metalsoft/.ssh /opt/metalsoft/mon /opt/metalsoft/nfs-storage || { echo "ERROR: unable to create folders in /opt/"; exit 3; }

debuglog "Checking DCONF"

if [ -z "$DCCONF" ];then
  echo
  echo Help:
  echo Before you start, make sure you have copied the SSL pem to this server, as the script will ask for a file path or provided the PEM via SSL_B64 variable
  echo If you save the ssl to /root/agents-ssl.pem it will be automatically picked up and copied to /opt/metalsoft/agents/ssl-cert.pem
  echo
  echo You must specify the configuration URL for your Datacenter ID as DCCONF, or if you use metalcloud-cli, you can pull a one-liner with:
  echo 'DCCONF="$(metalcloud-cli datacenter get --id uk-london --return-config-url)" SSL_HOSTNAME=yourhost.metalsoft.io [ NONINTERACTIVE_MODE=1 REGISTRY_LOGIN=base64HashOfRegistryCredentials SSL_B64=base64OfSslKeyAndCertPemFormat [ or SSL_PULL_URL=https://url.to/ssl.pem ] ] bash <(curl -sk https://raw.githubusercontent.com/metalsoft-io/scripts/main/deploy-agents.sh)'
  echo
  exit 0
fi

debuglog "Pulling DC config URL"
DCCONFDOWNLOADED="$(wget -q --connect-timeout=20 --tries=4 --no-check-certificate -O - "${DCCONF}")"

debuglog "Enabling nfs/nfsd kernel modules"
test -f /usr/lib/modules/$(uname -r)/kernel/fs/nfs/nfs.ko && modprobe nfs && if ! grep -E '^nfs$' /etc/modules > /dev/null;then echo nfs >> /etc/modules;fi || { echo "no nfs kernel module found in current kernel modules, needed for docker nfs container" && exit 1; }
test -f /usr/lib/modules/$(uname -r)/kernel/fs/nfsd/nfsd.ko && modprobe nfsd && if ! grep -E '^nfsd$' /etc/modules > /dev/null;then echo nfsd >> /etc/modules;fi || { echo "no nfsd kernel module found in current kernel modules, needed for docker nfs container" && exit 1; }

test ! -f /usr/share/keyrings/docker-archive-keyring.gpg && \
cat > /tmp/docker-archive-keyring.gpg <<ENDD
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
YT90qFF93M3v01BbxP+EIY2/9tiIPbrd
=0YYh
-----END PGP PUBLIC KEY BLOCK-----
ENDD

cat /tmp/docker-archive-keyring.gpg | gpg --batch --yes --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

debuglog "Ensuring Docker is installed"
command -v docker > /dev/null || { debuglog "Install docker" && \
  echo   "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list && \
  debuglog "Apt update.." && \
  apt-get update -qq && \
  debuglog "Apt installing docker-ce docker-ce-cli containerd.io docker-compose-plugin .." && \
  apt-get -y install docker-ce docker-ce-cli containerd.io docker-compose-plugin >/dev/null; }

debuglog "Checking if 'docker compose' is available"
docker compose >/dev/null 2>&1 || { debuglog "Installing docker-compose-plugin" && apt-get update -qq && apt-get -y install docker-compose-plugin; }

  # debuglog "Ensuring docker-compose is installed"
  # test -x /usr/local/bin/docker-compose || { debuglog "Installing docker-compose" && curl -skL "$(curl -s https://api.github.com/repos/docker/compose/releases/latest|grep browser_download_url|grep "$(uname -s|tr '[:upper:]' '[:lower:]')-$(uname -m)"|grep -v sha25|head -1|cut -d'"' -f4)" -o /usr/local/bin/docker-compose && chmod +x /usr/local/bin/docker-compose; } || { debuglog "Installing docker-compose" && curl -skL "$(curl -s https://api.github.com/repos/docker/compose/releases/latest|jq -r '.assets[] | select(.name=="docker-compose-linux-'$(uname -m)'") | .browser_download_url')" -o /usr/local/bin/docker-compose && chmod +x /usr/local/bin/docker-compose; }

debuglog "Checking provided SSL"
test -n "$SSL_B64" && echo -n "$SSL_B64"|base64 -d > /opt/metalsoft/agents/ssl-cert.pem

if [ ! -f /opt/metalsoft/agents/ssl-cert.pem ];then
  SSL_PULL_URL="${SSL_PULL_URL}" manageSSL
  while [ $? -ne 0 ]; do
    manageSSL
  done
fi

if [ -z "$SSL_HOSTNAME" ];then
  read -p "Enter SSL hostname [${DISCOVERED_SSL_HOSTNAME}]: " name
  SSL_HOSTNAME=${name:-$DISCOVERED_SSL_HOSTNAME}
  debuglog "SSL_HOSTNAME set to: $SSL_HOSTNAME"
fi

debuglog "Setting DATACENTERNAME"
DCAURL="${AGENTS_IMG:-$DCAGENTS_URL}"
DATACENTERNAME="$(echo "${DCCONFDOWNLOADED}" | jq -r .currentDatacenter)"

if [ -z "$DATACENTERNAME" ];then
  DATACENTERNAME=$(echo "$DCCONF" | head -1 | grep -oP '(?<=datacenter_name=)[a-z0-9\-\_]+')
fi

HOSTNAMERANDOM=$(echo ${RANDOM} | md5sum | head -c 5)

if [ -n "$DOCKERENV" ];then
  cat > /opt/metalsoft/agents/.env <<ENDD
TAG=${IMAGES_TAG_SAVED}
ENDD
fi

if [ ! -f /opt/metalsoft/agents/docker-compose.yaml ] || [ "$FORCE" == "1" ] ;then
  debuglog "Creating /opt/metalsoft/agents/docker-compose.yaml"
  cat > /opt/metalsoft/agents/docker-compose.yaml <<ENDD
version: '3'
services:
  agents:
    network_mode: host
    container_name: agents
    image: ${DCAURL}
    restart: always
    privileged: true
    #command: bash -c "update-ca-certificates"
    volumes:
      - /opt/metalsoft/BSIAgentsVolume:/etc/BSIDatacenterAgents
      - /opt/metalsoft/logs:/var/log
      - /opt/metalsoft/.ssh:/root/.ssh
      - /opt/metalsoft/mon:/var/lib/mon/data
      - /etc/ssl/certs:/etc/ssl/certs
      - /usr/local/share/ca-certificates:/usr/local/share/ca-certificates
      - /usr/share/ca-certificates:/usr/share/ca-certificates
      # Use only if custom CA is needed
      #- /opt/metalsoft/agents/supervisor.conf:/var/vhosts/datacenter-agents-binary-compiled/supervisor.conf
    ports:
      - 9080:9080/tcp
      - 8067:8067/tcp
      - 3205:3205/tcp
      - 8069:8069/tcp
      - 8080:8080/tcp
      - 81:81/tcp
      - 53:53/tcp
      - 53:53/udp
      - 35280:35280/udp
      - 3205:3205/udp
      - 67:67/udp
      - 69:69/udp
      - 6343:6343/udp
    environment:
      - TZ=Etc/UTC
      - URL=${DCCONF}
      #- NODE_TLS_REJECT_UNAUTHORIZED=0
      # Use only if custom CA is needed
      #- NODE_EXTRA_CA_CERTS=/etc/ssl/certs/metalsoft_ca.pem
    hostname: agents-${DATACENTERNAME}-${HOSTNAMERANDOM}
  haproxy:
    network_mode: host
    container_name: dc-haproxy
    image: registry.metalsoft.dev/datacenter-agents-compiled/dc-haproxy:latest
    restart: always
    privileged: true
    volumes:
      - /opt/metalsoft/agents/haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg
      - /opt/metalsoft/agents/ssl-cert.pem:/etc/ssl/certs/poc.metalsoft.io.pem
    environment:
      - TZ=Etc/UTC
    hostname: dc-haproxy
  junos-driver:
    network_mode: bridge
    container_name: junos-driver
    image: ${JUNOSDRIVER_URL}
    restart: always
    ports:
      - 8006:5000/tcp
    environment:
      - TZ=Etc/UTC
    hostname: junos-driver
  ms-agent:
    container_name: ms-agent
    network_mode: host
    hostname: ms-agent-${DATACENTERNAME}-${HOSTNAMERANDOM}
    image: ${MSAGENT_URL}
    restart: always
    environment:
      - TZ=Etc/UTC
      - AGENT_ID=${DATACENTERNAME}-${HOSTNAMERANDOM}
      - AGENT_SECRET=${MS_TUNNEL_SECRET}
      - DATACENTER_ID=${DATACENTERNAME}
      - MONITORING_SERVICE_PORT=8099
      - LOG_LEVEL=debug
      - CONTROLLER_WS_URI=wss://${SSL_HOSTNAME}/tunnel-ctrl
      - CONTROLLER_TCP_ADDRESS=${SSL_HOSTNAME}:9091
      - CONTROLLER_VNC_URI=wss://${SSL_HOSTNAME}/agent-vnc
      - HTTP_PROXY=enabled
      - FILE_TRANSFER=enabled
      - SWITCH_SUBSCRIPTION=enabled
      - VNC=enabled
      - COMMAND_EXECUTION=enabled
      - OS_IMAGES_MOUNT=/iso
      - NFS_HOST=${MAINIP}:/data
    volumes:
      - /opt/metalsoft/nfs-storage:/iso
      - /etc/ssl/certs:/etc/ssl/certs
  nfs:
    network_mode: host
    container_name: nfs-server
    image: registry.metalsoft.dev/datacenter-agents-compiled/nfs-server:2.2.1
    restart: unless-stopped
    privileged: true
    environment:
      - NFS_EXPORT_0=/data                *(ro,no_subtree_check)
      - NFS_EXPORT_1=/data/test-iso       *(ro,no_auth_nlm)
    volumes:
      - /opt/metalsoft/nfs-storage:/data
    ports:
      - 2049:2049
      - 111:111
      - 32765:32765
      - 32767:32767

ENDD
fi

if [ ! -f /opt/metalsoft/agents/haproxy.cfg ] || [ "$FORCE" == "1" ] ;then
  debuglog "Creating /opt/metalsoft/agents/haproxy.cfg"
  cat > /opt/metalsoft/agents/haproxy.cfg <<ENDD
global
    chroot /var/lib/haproxy
    user root
    group root
    daemon
    ssl-default-bind-options no-sslv3 no-tls-tickets
    ssl-default-bind-ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256
    ssl-default-server-options no-sslv3 no-tls-tickets
    ssl-default-server-ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256
defaults
    mode http
    log stdout format raw local0

    retries 3
    timeout connect 10s
    timeout client 100m
    timeout server 30m
    timeout check 10s
    timeout http-keep-alive 10s
    timeout queue 10m
    timeout http-request 30m
    timeout tunnel 480m
    maxconn 3000
    option httpclose
    option forwardfor except 127.0.0.0/8
    option redispatch
    option abortonclose
    option httplog
    option dontlognull
    option http-server-close

frontend ft_local_apache_80
    mode http
    bind :80
    bind 127.0.0.1:80
    acl host_ws path_beg -i /api-ws
    acl host_dhcpe path_beg -i /dhcpe
    acl host_tftp path_beg -i /tftp8069
    acl host_dhcpe path_beg -i /os-ready
    acl host_repo hdr_dom(Host) -i repo.${SSL_HOSTNAME}
    acl has_special_uri path_beg /remote-console
    acl has_iso_uri path_beg /iso
    use_backend bk_local_apache_8080 if host_ws
    use_backend bk_fullmetal_dhcpe_8067 if host_dhcpe
    use_backend bk_fullmetal_tftpe_8069 if host_tftp
    use_backend bk_fullmetal_dhcpe_8067 if host_dhcpe
    use_backend bk_repo_443 if host_repo
    use_backend bk_guacamole_tomcat_8080 if has_special_uri
    use_backend bk_msagents_8099 if has_iso_uri
    default_backend bk_local_apache_81

frontend ft_local_apache_443
    mode http
    bind :443 ssl crt /etc/ssl/certs/poc.metalsoft.io.pem
    acl host_ws path_beg -i /api-ws
    acl host_dhcpe path_beg -i /dhcpe
    acl host_tftp path_beg -i /tftp8069
    acl host_dhcpe path_beg -i /os-ready
    acl host_repo hdr_dom(Host) -i repo.${SSL_HOSTNAME}
    acl has_special_uri path_beg /remote-console
    http-response add-header Strict-Transport-Security max-age=157680001
    use_backend bk_local_apache_8080 if host_ws
    use_backend bk_fullmetal_dhcpe_8067 if host_dhcpe
    use_backend bk_fullmetal_tftpe_8069 if host_tftp
    use_backend bk_fullmetal_dhcpe_8067 if host_dhcpe
    use_backend bk_repo_443 if host_repo
    use_backend bk_guacamole_tomcat_8080 if has_special_uri
    default_backend bk_local_apache_81

backend bk_fullmetal_dhcpe_8067
    server localhost 127.0.0.1:8067

    http-request set-header X-HAPROXY-OUTSIDE-SAFE %[src]
    option forwardfor header X-HAPROXY-OUTSIDE-IP

backend bk_fullmetal_tftpe_8069
    server localhost 127.0.0.1:8069

    http-request set-header X-HAPROXY-OUTSIDE-SAFE %[src]
    option forwardfor header X-HAPROXY-OUTSIDE-IP

backend bk_local_apache_81
    server localhost 127.0.0.1:81

        http-request set-header X-HAPROXY-OUTSIDE-SAFE %[src]
    option forwardfor header X-HAPROXY-OUTSIDE-IP

backend bk_local_apache_8080
    server localhost 127.0.0.1:8080

    http-request set-header X-HAPROXY-OUTSIDE-SAFE %[src]
    option forwardfor header X-HAPROXY-OUTSIDE-IP

backend bk_guacamole_tomcat_8080
    server localhost 127.0.0.1:8081

backend bk_repo_443
    server repo.poc.metalsoft.io 127.0.0.1:9080

backend bk_msagents_8099
    server localhost 127.0.0.1:8099
ENDD
fi

test -n "${CLI_DCCONF}" && CLI_DCCONF="$(echo -n "${CLI_DCCONF}"|sed 's/&/\\&/g' )" && sed -i "s,\(\s\+\- URL=\).*,\1${CLI_DCCONF},g" /opt/metalsoft/agents/docker-compose.yaml
test -n "${CLI_MS_TUNNEL_SECRET}" && sed -i "s/\(\s\+\- AGENT_SECRET=\).*/\1${CLI_MS_TUNNEL_SECRET}/g" /opt/metalsoft/agents/docker-compose.yaml
test -n "${CLI_DATACENTERNAME}" && sed -i "s/\(\s\+\- DATACENTER_NAME=\).*/\1${CLI_DATACENTERNAME}/g" /opt/metalsoft/agents/docker-compose.yaml && \
sed -E "s/(\s+?hostname: agents-)(\S+)(-\w+)/\1${CLI_DATACENTERNAME}\3/gm" /opt/metalsoft/agents/docker-compose.yaml
if [[ -n $CUSTOM_CA ]]; then
  cat > /opt/metalsoft/agents/supervisor.conf <<ENDD
[supervisord]
nodaemon=true
environment=
    NODE_EXTRA_CA_CERTS=/etc/ssl/certs/${CUSTOM_CA},
    NODE_OPTIONS="--use-openssl-ca"

[unix_http_server]
file=/var/run/supervisor.sock
chmod=0700

[rpcinterface:supervisor]
supervisor.rpcinterface_factory = supervisor.rpcinterface:make_main_rpcinterface

[supervisorctl]
serverurl=unix:///var/run/supervisor.sock

[program:BSI]
command=/var/vhosts/datacenter-agents-binary-compiled/BSI/BSI --expose-gc --use-openssl-ca
autostart=true
autorestart=true
stderr_logfile=/var/log/BSI.err.log
stdout_logfile=/var/log/BSI.out.log

[program:DHCP]
command=/var/vhosts/datacenter-agents-binary-compiled/DHCP/DHCP --expose-gc --use-openssl-ca
autostart=true
autorestart=true
stderr_logfile=/var/log/DHCP.err.log
stdout_logfile=/var/log/DHCP.out.log


[program:TFTP]
command=/var/vhosts/datacenter-agents-binary-compiled/TFTP/TFTP --expose-gc
autostart=true
autorestart=true
stderr_logfile=/var/log/TFTP.err.log
stdout_logfile=/var/log/TFTP.out.log

[program:DNS]
command=/var/vhosts/datacenter-agents-binary-compiled/DNS/DNS --expose-gc --use-openssl-ca
autostart=true
autorestart=true
stderr_logfile=/var/log/DNS.err.log
stdout_logfile=/var/log/DNS.out.log

[program:iSNS]
command=/var/vhosts/datacenter-agents-binary-compiled/iSNS/iSNS --expose-gc --use-openssl-ca
autostart=true
autorestart=true
stderr_logfile=/var/log/iSNS.err.log
stdout_logfile=/var/log/iSNS.out.log

[program:Power]
command=/var/vhosts/datacenter-agents-binary-compiled/Power/Power --expose-gc --use-openssl-ca
autostart=true
autorestart=true
stderr_logfile=/var/log/Power.err.log
stdout_logfile=/var/log/Power.out.log

[program:AnsibleRunner]
command=/var/vhosts/datacenter-agents-binary-compiled/AnsibleRunner/AnsibleRunner --expose-gc --use-openssl-ca
autostart=true
autorestart=true
stderr_logfile=/var/log/AnsibleRunner.err.log
stdout_logfile=/var/log/AnsibleRunner.out.log

[program:Monitoring]
command=/usr/local/bin/node --expose-gc --use-openssl-ca /var/vhosts/datacenter-agents-binary-compiled/Monitoring/Monitoring.portable.js
autostart=true
autorestart=true
stderr_logfile=/var/log/Monitoring.err.log
stdout_logfile=/var/log/Monitoring.out.log
ENDD

sed -i "s/\#\- \/opt\/metalsoft\/agents\/supervisor\.conf/\- \/opt\/metalsoft\/agents\/supervisor.conf/g" /opt/metalsoft/agents/docker-compose.yaml

fi

debuglog "Login to docker with Metalsoft provided credentials for registry.metalsoft.dev:"
mkdir -p "${HOME}/.docker"
test -n "${REGISTRY_LOGIN}" && echo "{\"auths\":{\"registry.metalsoft.dev\":{\"auth\":\"${REGISTRY_LOGIN}\"}}}" > "${HOME}/.docker/config.json"

docker login registry.metalsoft.dev

while [ $? -ne 0 ]; do
  debuglog "Lets try docker login again:"
  docker login registry.metalsoft.dev
  sleep 1
done

debuglog "starting docker containers"
systemctl start docker.service
cd /opt/metalsoft/agents
debuglog "pulling latest images.."
docker compose pull
docker compose up -d

if [[ "${NONINTERACTIVE_MODE}" != 1 ]];then
  sleep 2
  docker ps
  sleep 2
  docker ps
fi

if [ -f /etc/ssh/ms_banner ];then
  debuglog "update /etc/ssh/ms_banner"
  if grep -q '^AgentIP:' /etc/ssh/ms_banner;then sed -i "/^AgentIP:.*/c AgentIP: $(ip r get 1|head -1|awk '{print $7}')" /etc/ssh/ms_banner;else echo "AgentIP: $(ip r get 1|head -1|awk '{print $7}')" >> /etc/ssh/ms_banner;fi
  dcurl="$(grep ' URL=' /opt/metalsoft/agents/docker-compose.yaml|grep -oP '.* URL=\K.*'|cut -d/ -f1-3)" && if grep -q '^Controller:' /etc/ssh/ms_banner;then sed -i "/^Controller:.*/c Controller: $dcurl" /etc/ssh/ms_banner;else echo "Controller: $dcurl" >> /etc/ssh/ms_banner;fi
  dcname="$(grep ' DATACENTER_NAME=' /opt/metalsoft/agents/docker-compose.yaml|cut -d= -f2)" && if grep -q '^Datacenter:' /etc/ssh/ms_banner;then sed -i "/^Datacenter:.*/c Datacenter: $dcname" /etc/ssh/ms_banner;else echo "Datacenter: $dcname" >> /etc/ssh/ms_banner;fi
fi

debuglog "Pulling discovery ISO"
test ! -f /opt/metalsoft/nfs-storage/BDK.iso && wget -O /opt/metalsoft/nfs-storage/BDK.iso https://repo.metalsoft.io/.tftp/BDK_CentOS-7-x86_64.iso

debuglog "Stop and disable host systemd-resolved.service, which will be replaced by agent's DNS docker container"
systemctl disable --now systemd-resolved.service
systemctl disable --now rpcbind || true
systemctl disable --now rpcbind.socket || true
systemctl daemon-reload

debuglog "Add DNS resolvers to /etc/resolv.conf"
test -L /etc/resolv.conf && \rm -f /etc/resolv.conf 
find /etc/netplan -type f | while read -r netplan_file; do
  nameservers=$(parse_yaml $netplan_file | grep nameservers | cut -d "=" -f 2 | tr -d '"[]' | sed -e "s/,/ /g")
  for nameserver in $nameservers; do
    echo "nameserver $nameserver"
    if [[ $nameserver != $(grep $nameserver /etc/resolv.conf | cut -d" " -f2) ]];then
      echo "nameserver $nameserver" >> /etc/resolv.conf
    fi
  done
done
if [[ -z $(grep nameserver /etc/resolv.conf) ]];then
  echo -e "nameserver 1.1.1.1\nnameserver 8.8.8.8" > /etc/resolv.conf
fi

debuglog "[ ${SECONDS} sec ] All done. To check containers, use: docker ps" success
