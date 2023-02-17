#!/bin/bash
# set -x
echo "whoami: $(whoami)"
export LC_ALL=C
export DEBIAN_FRONTEND=noninteractive
export APT_LISTCHANGES_FRONTEND=none
test -z "$DCAGENTS_URL" && DCAGENTS_URL='registry.metalsoft.dev/datacenter-agents-compiled/datacenter-agents-compiled-v2:5.0'
test -z "$WSTCLIENT_URL" && WSTCLIENT_URL='registry.metalsoft.dev/datacenter-agents-compiled/websocket-tunnel-client:v5.0'
MAINIP="$(hostname -I 2>/dev/null | awk '{print $1}')"
test -z "$MAINIP" && MAINIP="$(ip r get 1|head -1|awk '{print $7}')"
test -z "$SSL_HOSTNAME" && SSL_HOSTNAME="$(echo "$DCCONF"|cut -d/ -f3)"

function testOS
{
  echo :: testing OS version
  if ! grep -q "Ubuntu 2" /etc/issue; then
    echo
    echo "This script is only compatible with Ubuntu 20+ Operating system"
    echo "and will not run on any other OS"
    echo
    exit 2
  fi
}

function nc_check_remote_conn {

nc=$(tput sgr0)
bold=$(tput bold)
orange=$(tput setaf 3)
lightred=$(tput setaf 9)
lightgreen=$(tput setaf 10)

	ip=$1
	port=$2
	protocol=${3:-tcp}
	comment="$4 "
	test "$protocol" == 'icmp' && port=icmp

  command -v curl  > /dev/null && command -v update-ca-certificates > /dev/null && command -v dig > /dev/null && command -v jq > /dev/null || { echo :: installing required packages && \
    apt update -qq && \
    apt -yqqqq install curl ca-certificates net-tools jq dnsutils; }

	echo -n "Conn check from ${bold}${MAINIP}${nc} to ${comment}${orange}$ip:$port${nc}: "

	if [[ ! $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
		ip="$(dig +short "$ip"|grep -Po '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' |xargs)"
	fi
	for ip in $ip;do

		if [ "$protocol" == "tcp" ];then
			nc -nzw 5 "$ip" "$port" >/dev/null 2>&1 && echo "${lightgreen}success${nc}" || echo "${lightred}failure${nc}"
		elif [ "$protocol" == "icmp" ];then
			ping -c2 "$ip" >/dev/null 2>&1 && echo "${lightgreen}success${nc}" || echo "${lightred}failure${nc}"
		else
			nc -nzuw 5 "$ip" "$port" >/dev/null 2>&1 && echo "${lightgreen}success${nc}" || echo "${lightred}failure${nc}"

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
  test -z "${ssl}" && echo ":: Please provide path of the SSL pem:" && read -r -e -p "Path to SSL pem: " ssl
  if [ -r "$ssl" ];then
    DISCOVERED_SSL_HOSTNAMES="$(openssl x509 -in "$ssl" -noout -text 2>/dev/null|grep DNS:|head -1)"
    DISCOVERED_SSL_HOSTNAME="$(echo "$DISCOVERED_SSL_HOSTNAMES"|sed 's/,\s\+/\n/g;'|sed 's/.*DNS://g'|cut -d. -f2-10|head -1)"
    if [ -z "$DISCOVERED_SSL_HOSTNAME" ];then
      echo WARNING: no hostname discovered in SSL file
      # return 1
    fi
    if cp "$ssl" /opt/metalsoft/agents/ssl-cert.pem;then
      echo :: copied "$ssl" to /opt/metalsoft/agents/ssl-cert.pem. Found SSL hosts: "$DISCOVERED_SSL_HOSTNAMES"
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

if [ -z "$DCCONF" ];then
  echo
  echo Help:
  echo Before you start, make sure you have copied the SSL pem to this server, as the script will ask for a file path
  echo If you save the ssl to /root/agents-ssl.pem it will be automatically picked up and copied to /opt/metalsoft/agents/ssl-cert.pem
  echo
  echo You must specify the configuration URL for your Datacenter ID as DCCONF, or if you use metalcloud-cli, you can pull a one-liner with:
  echo 'DCCONF="$(metalcloud-cli datacenter get --id uk-london --return-config-url)" SSL_HOSTNAME=yourhost.metalsoft.io [ NONINTERACTIVE_MODE=1 REGISTRY_LOGIN=base6HashOfCredentials SSL_PULL_URL=https://url.to/ssl.pem GUACAMOLE_KEY=your_guacamole_key_provided_by_metalsoft WEBSOCKET_TUNNEL_SECRET=WESOCKET_TUNNEL_KEY_provided_by_metalsoft ] bash <(curl -sk https://raw.githubusercontent.com/metalsoft-io/scripts/main/deploy-agents.sh)'
  echo
  exit 0
  fi
  # echo DCCONF $DCCONF
  # export DCCONF="$DCCONF"

  DCCONFDOWNLOADED=$(wget -q --no-check-certificate -O - "${DCCONF}")

  mkdir -p /opt/metalsoft/BSIAgentsVolume /opt/metalsoft/logs /opt/metalsoft/logs_agents /opt/metalsoft/agents /opt/metalsoft/containerd /opt/metalsoft/.ssh /opt/metalsoft/mon /opt/metalsoft/nfs-storage || { echo "ERROR: unable to create folders in /opt/"; exit 3; }

  test -f /usr/lib/modules/$(uname -r)/kernel/fs/nfs/nfs.ko && modprobe nfs && if ! grep -E '^nfs$' /etc/modules > /dev/null;then echo nfs >> /etc/modules;fi || { echo "no nfs kernel module found in current kernel modules, needed for docker nfs container" && exit 1; }
  test -f /usr/lib/modules/$(uname -r)/kernel/fs/nfsd/nfsd.ko && modprobe nfsd && if ! grep -E '^nfsd$' /etc/modules > /dev/null;then echo nfsd >> /etc/modules;fi || { echo "no nfsd kernel module found in current kernel modules, needed for docker nfs container" && exit 1; }

  if ! grep -q 1.1.1.1 /etc/resolv.conf;then echo "nameserver 1.1.1.1" >> /etc/resolv.conf;fi
  if ! grep -q 8.8.8.8 /etc/resolv.conf;then echo "nameserver 8.8.8.8" >> /etc/resolv.conf;fi


  command -v docker > /dev/null || { echo :: Install docker && \
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --batch --yes --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg && \
    echo   "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list && \
    apt update -qq && apt -yqqqq upgrade && \
    apt-get -yqqqq install docker-ce docker-ce-cli containerd.io; }

  test -x /usr/local/bin/docker-compose || { echo :: Install docker-compose && curl -skL "$(curl -s https://api.github.com/repos/docker/compose/releases/latest|grep browser_download_url|grep "$(uname -s|tr '[:upper:]' '[:lower:]')-$(uname -m)"|grep -v sha25|head -1|cut -d'"' -f4)" -o /usr/local/bin/docker-compose && chmod +x /usr/local/bin/docker-compose; }

  if [ ! -f /usr/local/share/ca-certificates/metalsoft_ca.crt ];then
    wget https://repo.metalsoft.io/.tftp/metalsoft_ca.crt -O /usr/local/share/ca-certificates/metalsoft_ca.crt && cp /usr/local/share/ca-certificates/metalsoft_ca.crt /etc/ssl/certs/ && update-ca-certificates
  fi

  if [ ! -f /opt/metalsoft/agents/ssl-cert.pem ];then
    SSL_PULL_URL="${SSL_PULL_URL}" manageSSL
    while [ $? -ne 0 ]; do
      manageSSL
    done
  fi

  if [ -z "$SSL_HOSTNAME" ];then
    read -p "Enter SSL hostname [${DISCOVERED_SSL_HOSTNAME}]: " name
    SSL_HOSTNAME=${name:-$DISCOVERED_SSL_HOSTNAME}
    echo SSL_HOSTNAME set to: "$SSL_HOSTNAME"
  fi

  if [[ "${NONINTERACTIVE_MODE}" == 1 ]];then
    GUACAMOLE_KEY="${GUACAMOLE_KEY:-__GUACAMOLE_KEY_NEEDS_TO_BE_SET__}"
  else
    if [ -z "$GUACAMOLE_KEY" ];then
      read -p "Enter GUACAMOLE_KEY: " gckey
      GUACAMOLE_KEY=${gckey:-__GUACAMOLE_KEY_NEEDS_TO_BE_SET__}
      echo GUACAMOLE_KEY set to: "$GUACAMOLE_KEY"
    fi
  fi

  if [[ "${NONINTERACTIVE_MODE}" == 1 ]];then
    WEBSOCKET_TUNNEL_SECRET="${WEBSOCKET_TUNNEL_SECRET:-__WEBSOCKET_TUNNEL_SECRET_NEEDS_TO_BE_SET__}"
  else
    if [ -z "$WEBSOCKET_TUNNEL_SECRET" ]; then
      read -p "Enter WEBSOCKET_TUNNEL_SECRET: " wstunkey
      WEBSOCKET_TUNNEL_SECRET=${wstunkey:-__WEBSOCKET_TUNNEL_SECRET_NEEDS_TO_BE_SET__}
      echo WEBSOCKET_TUNNEL_SECRET set to: "$WEBSOCKET_TUNNEL_SECRET"
    fi
  fi

  DCAURL="${AGENTS_IMG:-$DCAGENTS_URL}"
  DATACENTERNAME="$(echo "${DCCONFDOWNLOADED}" | jq -r .currentDatacenter)"
  if [ -z "$DATACENTERNAME" ];then
    DATACENTERNAME=$(echo "$DCCONF" | head -1 | grep -oP '(?<=datacenter_name=)[a-z0-9\-\_]+')
  fi
  HOSTNAMERANDOM=$(echo ${RANDOM} | md5sum | head -c 5)
  if [ ! -f /opt/metalsoft/agents/docker-compose.yaml ] || [ "$FORCE" == "1" ] ;then
    echo :: Creating /opt/metalsoft/agents/docker-compose.yaml
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
      - /opt/metalsoft/logs_agents:/root/.pm2/logs
      - /opt/metalsoft/logs:/var/log
      - /opt/metalsoft/.ssh:/root/.ssh
      - /opt/metalsoft/mon:/var/lib/mon/data
      #- /etc/ssl/certs:/etc/ssl/certs
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
  remote-console:
    network_mode: host
    container_name: dc-remoteconsole
    image: registry.metalsoft.dev/datacenter-agents-compiled/bsi-guac:latest
    restart: always
    privileged: true
    environment:
      - TZ=Etc/UTC
      - GUACAMOLE_BSI_GUACAMOLE_ENDPOINT_URL=https://${SSL_HOSTNAME}/api/internal/ipc_guacamole
      - GUACAMOLE_BSI_GUACAMOLE_ENPOINT_SALT_API_KEY=${GUACAMOLE_KEY}
  junos-driver:
    network_mode: bridge
    container_name: junos-driver
    image: registry.metalsoft.dev/datacenter-agents-compiled/junos-driver:integration
    restart: always
    ports:
      - 8006:5000/tcp
    environment:
      - TZ=Etc/UTC
    hostname: junos-driver
  websocket-tunnel-client:
    image: ${WSTCLIENT_URL}
    container_name: websocket-tunnel-client
    restart: always
    hostname: websocket-tunnel-client
    environment:
      - DATACENTER_NAME=${DATACENTERNAME}
      - ERROR_LOG_LEVEL=debug
      - CONTROLLER_SCHEMA=https
      - CONTROLLER_TUNNEL_HOST=${SSL_HOSTNAME}
      - CONTROLLER_TUNNEL_PORT=9010
      - CONTROLLER_TCP_PORT=9011
      - DISABLE_SSL_CHECKS=true
      - OS_IMAGES_MOUNT=/iso
      - NFS_HOST=${MAINIP}:/data
      - DEBUG=*
      - DATACENTERS_SECRET=${WEBSOCKET_TUNNEL_SECRET}
      - GUACAMOLE_PLUGIN_HOST=${MAINIP}
      - GUACAMOLE_PLUGIN_PORT=8081
    volumes:
      - /opt/metalsoft/nfs-storage:/iso
      - /etc/hosts:/etc/hosts
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
  echo :: Creating /opt/metalsoft/agents/haproxy.cfg
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
    log global

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
    use_backend bk_local_apache_8080 if host_ws
    use_backend bk_fullmetal_dhcpe_8067 if host_dhcpe
    use_backend bk_fullmetal_tftpe_8069 if host_tftp
    use_backend bk_fullmetal_dhcpe_8067 if host_dhcpe
    use_backend bk_repo_443 if host_repo
    use_backend bk_guacamole_tomcat_8080 if has_special_uri
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
ENDD
fi

echo :: Login to docker with Metalsoft provided credentials for registry.metalsoft.dev:
mkdir -p "${HOME}/.docker"
test -n "${REGISTRY_LOGIN}" && echo "{\"auths\":{\"registry.metalsoft.dev\":{\"auth\":\"${REGISTRY_LOGIN}\"}}}" > "${HOME}/.docker/config.json"

docker login registry.metalsoft.dev
while [ $? -ne 0 ]; do
  echo :: Lets try docker login again:
  docker login registry.metalsoft.dev
  sleep 1
done

echo ":: Stop and disable host systemd-resolved.service, which will be replaced by agent's DNS docker container"
systemctl disable --now systemd-resolved.service
systemctl disable --now rpcbind || true
systemctl disable --now rpcbind.socket || true
test -L /etc/resolv.conf && \rm -f /etc/resolv.conf &&  echo -e "nameserver 1.1.1.1\nnameserver 8.8.8.8" > /etc/resolv.conf

echo :: starting docker containers
systemctl start docker.service
cd /opt/metalsoft/agents
if [[ "${NONINTERACTIVE_MODE}" == 1 ]];then
  echo :: pulling latest images..
  docker-compose pull -q
else
  docker-compose pull
fi
docker-compose up -d
if [[ "${NONINTERACTIVE_MODE}" != 1 ]];then
  sleep 2
  docker ps
  sleep 2
  docker ps
fi

if [ -f /etc/ssh/ms_banner ];then
  echo ":: update /etc/ssh/ms_banner"
  if grep -q '^IP:' /etc/ssh/ms_banner;then sed -i "/^IP:.*/c IP: $(ip r get 1|head -1|awk '{print $7}')" /etc/ssh/ms_banner;else echo "IP: $(ip r get 1|head -1|awk '{print $7}')" >> /etc/ssh/ms_banner;fi
  dcurl="$(grep ' URL=' /opt/metalsoft/agents/docker-compose.yaml|grep -oP '.* URL=\K.*'|cut -d/ -f1-3)" && if grep -q '^Controller:' /etc/ssh/ms_banner;then sed -i "/^Controller:.*/c Controller: $dcurl" /etc/ssh/ms_banner;else echo "Controller: $dcurl" >> /etc/ssh/ms_banner;fi
  dcname="$(grep ' DATACENTER_NAME=' /opt/metalsoft/agents/docker-compose.yaml|cut -d= -f2)" && if grep -q '^Datacenter:' /etc/ssh/ms_banner;then sed -i "/^Datacenter:.*/c Datacenter: $dcname" /etc/ssh/ms_banner;else echo "Datacenter: $dcname" >> /etc/ssh/ms_banner;fi
fi

echo :::: All done. to check containers, use: docker ps
