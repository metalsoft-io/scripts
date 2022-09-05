#!/bin/bash
#set -x


# TODO:
# Agents VM will also need to be able to reach the OOB (management) network over L3
# and for devices on the OOB network to be able to reach the agent over NFS, HTTP, HTTPs, NTP, DNS.
# For PXE it will also need inbound DHCP (via DHCP proxy), TFTP.



nc=$(tput sgr0)
bold=$(tput bold)
#red=$(tput setaf 1)
#green=$(tput setaf 2)
orange=$(tput setaf 3)
#blue=$(tput setaf 4)
#purple=$(tput setaf 5)
cyan=$(tput setaf 6)
#white=$(tput setaf 7)
gray=$(tput setaf 8)
lightred=$(tput setaf 9)
lightgreen=$(tput setaf 10)
yellow=$(tput setaf 11)
#lightblue=$(tput setaf 12)
#pink=$(tput setaf 13)
#black=$(tput setaf 16)

unset command_not_found_handle

which nc > /dev/null || { echo 'nc is needed for this script to run properly. Please install netcat' && exit 1; }
which dig > /dev/null || { echo 'dig is needed for this script to run properly. Please install dnsutils' && exit 1; }

localhost=$(hostname -i) || localhost=127.0.0.1

function usage {
	echo
	echo "${bold}Options:${nc}"
	echo "  ${bold}-a${nc} <agent_ip> ${gray} to check against${nc}"
	echo "  ${bold}-o${nc} <oob_ip> ${gray} to check against${nc}"
	echo "  ${bold}-n${nc} <node_ip> ${gray} to check against. Can be used multiple times${nc}"
	echo "  ${bold}-k${nc} ${gray} ${orange}flag ${gray}signifying that we have k8s already installed${nc}"
	echo "  ${bold}-p${nc} <port> ${gray} custom ssh port${nc}"
	echo
	echo "${bold}Examples:${nc}"
	echo "  ${yellow}$0 -a 172.31.255.254 -n 10.255.130.12 -n 10.255.130.13${nc}"
	echo "  ${yellow}$0 -a 172.31.255.254 -o 10.255.129.10${nc}"
	echo
	exit 0
}

if [ -z "$1" ];then usage;fi

usek8s=0
sshport=22
while getopts ":a:o:n:p:k" o; do
	case "${o}" in
		a) agentsIp=${OPTARG} ;;
		o) oobIp=${OPTARG} ;;
		k) usek8s=1 ;;
		n) nodes+=("${OPTARG}") ;;
		p) sshport=("${OPTARG}") ;;
		*) usage ;;
	esac
done
shift $((OPTIND-1))

#restOfIPs="$@"

#nodes_tcp_ports="$sshport 62013 10250"
#agents_tcp_ports="$sshport 53 80 443 9003 9009 9010 9011 9090 9091"
agents_tcp_ports="$sshport 53"
agents_udp_ports="53 67 69"
oob_tcp_ports="80 443 623 111 2049 32765 32767"
oob_udp_ports="623 53 67 69"
node1svcports="80 443 9003 9009 9010 9011 9090 9091"
node1svcportsudp="53"


function nc_start_listener_and_check_remote_ip_port {
	# start listener on remote ip:port and then connect to it
	ip=$1
	port=$2
	protocol=${3:-tcp}
	to=${4:-10}
	proto=''
	comment="${5} "

	sleeper=2
	if [ "$protocol" == 'udp' ];then
		proto='u'
	fi
	# initiate listener on remote box for the specified port for some time and put this process in the background
	echo -n "Creating listener on ${orange}$ip:$port${nc} (if port not already in use) and connecting to it from here: "
	ssh -A -p $sshport -o StrictHostKeyChecking=no -o LogLevel=ERROR -o ConnectTimeout=$to -l root $ip "if ! ss -l${proto} -n|grep -P ':${port}\b' >/dev/null;then timeout $to nc -n${proto} -l -s 0.0.0.0 -p ${port};fi" 2>/dev/null &
	sleep $sleeper
	nc -nz${proto}w $(expr $to - $sleeper) $ip $port >/dev/null 2>&1 && echo ${lightgreen}success${nc} || echo ${lightred}failure${nc}

}
function nc_connect_back_from_remote_ip_port {
	connectToIp=$1
	pingIp=$2
	port=$3
	protocol=${4:-tcp}
	to=${5:-10}

	echo -n "From ${orange}$connectToIp${nc} to ${orange}$pingIp:$port${nc}: "

	if [[ ! $pingIp =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
		pingIp="$(dig +short $pingIp|grep -Po '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' |xargs)"
	fi
	for pingIp in $pingIp;do
		if [[ $port == 'icmp' ]];then
			test "$(ssh -A  -p $sshport -o StrictHostKeyChecking=no -o LogLevel=ERROR -o ConnectTimeout=20 -l root $connectToIp ping -c2 $pingIp >/dev/null 2>&1 && echo 0 || echo 1)" == "0" && echo ${lightgreen}success${nc} || echo ${lightred}failure${nc}
		else
			if [[ "$protocol" == 'udp' ]];then
				test "$(ssh -A  -p $sshport -o StrictHostKeyChecking=no -o LogLevel=ERROR -o ConnectTimeout=20 -l root $connectToIp nc -nzuw5 $pingIp $port >/dev/null 2>&1 && echo 0 || echo 1)" == "0" && echo ${lightgreen}success${nc} || echo ${lightred}failure${nc}
			else
				test "$(ssh -A  -p $sshport -o StrictHostKeyChecking=no -o LogLevel=ERROR -o ConnectTimeout=20 -l root $connectToIp nc -nzw5 $pingIp $port >/dev/null 2>&1 && echo 0 || echo 1)" == "0" && echo ${lightgreen}success${nc} || echo ${lightred}failure${nc}
			fi
		fi
	done
}
function nc_check_remote_conn {
	ip=$1
	port=$2
	protocol=${3:-tcp}
	comment="$4 "
	test "$protocol" == 'icmp' && port=icmp

	echo -n "From ${bold}${localhost}:$protocol${nc} to ${comment}${orange}$ip:$port${nc}: "

	if [[ ! $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
		ip="$(dig +short $ip|grep -Po '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' |xargs)"
	fi
	for ip in $ip;do

		if [ "$protocol" == "tcp" ];then
			nc -nzw 5 $ip $port >/dev/null 2>&1 && echo ${lightgreen}success${nc} || echo ${lightred}failure${nc}
		elif [ "$protocol" == "icmp" ];then
			ping -c2 $ip >/dev/null 2>&1 && echo ${lightgreen}success${nc} || echo ${lightred}failure${nc}
		else
			nc -nzuw 5 $ip $port >/dev/null 2>&1 && echo ${lightgreen}success${nc} || echo ${lightred}failure${nc}

		fi
	done
}



if [ $usek8s -eq 1 ];then
	# check if we already have kubectl and nodes ready
	k8snodeslist="$(kubectl get nodes --no-headers 2>/dev/null)"
	k8sNnodes="$(echo -e "$k8snodeslist"|awk '{print $1}'|wc -l || 0)"
	if [ $k8sNnodes -gt 0 ];then
		k8sNreadynodes="$(echo -e "$k8snodeslist"|grep Ready|awk '{print $1}'|wc -l || 0)"
		#k8snodes="$(echo -e "$k8snodeslist"|awk '{print $1}'|xargs)"
		checkedNodes=()
		checkedNodesNoColor=()
		shopt -s lastpipe
		echo -e "$k8snodeslist"|while read n;do
		nname=$(echo -n $n|awk '{print $1}')
		if [[ "$nname" != "$(hostname -f)" ]];then
			checkedNodesNoColor+=($nname)
		fi
		if echo "$n"|grep 'Ready' >/dev/null;then
			checkedNodes+=(${lightgreen}$nname)
		else
			checkedNodes+=(${lightred}$nname)
		fi
	done
	echo "${lightgreen}:: We have k8s nodes (${k8sNreadynodes}/${k8sNnodes} ready): ${bold}${checkedNodes[@]}${nc}"
else # no k8s running
	echo "${yellow}":: No k8s nodes found${nc}
	fi
else # if usek8s is not 1
	#echo no k8s
	if [[ "x${nodes[@]}" != "x" ]];then
		checkedNodesNoColor="${nodes[@]}"
	fi
fi
echo "${cyan}:: Checking local nodes for external connectivity: $z${nc}"
nc_check_remote_conn 1.1.1.1 'AGAINNOTNEEDED' icmp
nc_check_remote_conn 1.1.1.1 80 tcp
nc_check_remote_conn 1.1.1.1 443 tcp

nc_check_remote_conn downloads.dell.com 443 tcp
nc_check_remote_conn downloads.linux.hpe.com 80 tcp
nc_check_remote_conn repo.metalsoft.io 80 tcp
nc_check_remote_conn registry.metalsoft.dev 443 tcp
nc_check_remote_conn quay.io 443 tcp
nc_check_remote_conn gcr.io 443 tcp
nc_check_remote_conn cloud.google.com 443 tcp
nc_check_remote_conn helm.traefik.io 443 tcp
nc_check_remote_conn k8s.io 443 tcp
nc_check_remote_conn smtp.office365.com 587 tcp

if [ $usek8s -eq 1 ];then
	if [ -n "$node1svcports" ];then
		for nsvc in ${node1svcports};do
			clusterip=$(kubectl get svc -A|egrep ",?${nsvc}:.*\/TCP"|awk '{print $5}')
			test ! -z "$clusterip" && nc_check_remote_conn $clusterip $nsvc
		done
	fi
fi


for h in ${checkedNodesNoColor[@]};do
	if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
		i=$h
	else
		i="$(dig +short $h|grep -Po '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' |xargs)"
	fi
	for z in $i;do
		echo "${cyan}:: Checking ports for node: "$z" / $h${nc}"
		nc_check_remote_conn "$z" 'NOTNEEDED' icmp "[$h]"
		echo "${cyan}:: Checking nodes for external connectivity: $z${nc}"
		if nc -nzw 5 "$z" $sshport >/dev/null 2>&1;then
			nc_start_listener_and_check_remote_ip_port "$z" 10250 tcp 10 "[$h]"
			nc_connect_back_from_remote_ip_port "$z" $localhost 6443 tcp
			nc_connect_back_from_remote_ip_port "$z" 1.1.1.1 icmp "[$h]"
			nc_connect_back_from_remote_ip_port "$z" 1.1.1.1 80 tcp "[$h]"
			nc_connect_back_from_remote_ip_port "$z" 1.1.1.1 443 tcp "[$h]"

			nc_connect_back_from_remote_ip_port "$z" downloads.dell.com 443 tcp
			nc_connect_back_from_remote_ip_port "$z" downloads.linux.hpe.com 80 tcp
			nc_connect_back_from_remote_ip_port "$z" repo.metalsoft.io 80 tcp
			nc_connect_back_from_remote_ip_port "$z" registry.metalsoft.dev 443 tcp
			nc_connect_back_from_remote_ip_port "$z" quay.io 443 tcp
			nc_connect_back_from_remote_ip_port "$z" gcr.io 443 tcp
			nc_connect_back_from_remote_ip_port "$z" cloud.google.com 443 tcp
			nc_connect_back_from_remote_ip_port "$z" helm.traefik.io 443 tcp
			nc_connect_back_from_remote_ip_port "$z" k8s.io 443 tcp
			nc_connect_back_from_remote_ip_port "$z" smtp.office365.com 587 tcp

			if [ -n "$node1svcports" ];then
				for nsvc in ${node1svcports};do
					if [ $usek8s -eq 1 ];then
						clusterip=$(kubectl get svc -A|egrep ",?${nsvc}:.*\/TCP"|awk '{print $5}')
						test ! -z "$clusterip" && nc_connect_back_from_remote_ip_port "$z" $clusterip $nsvc tcp
					else
						nc_start_listener_and_check_remote_ip_port $h $nsvc tcp 10
					fi
				done
			fi

			if [ -n "$node1svcportsudp" ];then
				for nsvc in ${node1svcportsudp};do
					if [ $usek8s -eq 1 ];then
						clusterip=$(kubectl get svc -A|egrep ",?${nsvc}:.*\/UDP"|awk '{print $5}')
						test ! -z "$clusterip" && nc_connect_back_from_remote_ip_port "$z" $clusterip $nsvc udp
					else
						nc_start_listener_and_check_remote_ip_port $h $nsvc udp 10
					fi
				done
			fi
		else
			echo ${lightred}Could not SSH into "$z" port $sshport to perform remote checks${nc}
		fi

	done
done

if [ -n "$agentsIp" ];then
	for z in ${agentsIp};do
		echo "${cyan}:: Checking agents: ${z}${nc}"
		nc_check_remote_conn "$z" _ icmp '[agents]'

		if [ -n "$agents_tcp_ports" ];then
			for atp in $agents_tcp_ports;do
				nc_check_remote_conn "$z" $atp tcp '[agents]'
			done
		fi
		if [ -n "$agents_udp_ports" ];then
			for aup in $agents_udp_ports;do
				nc_check_remote_conn "$z" $aup udp '[agents]'
			done
		fi
		if nc -nzw 5 "$z" $sshport >/dev/null 2>&1;then
			if [ -n "$node1svcports" ];then
				for nsvc in ${node1svcports};do
					clusterip=$(kubectl get svc -A|egrep ",?${nsvc}:.*\/TCP"|awk '{print $5}')
					#test ! -z "$clusterip" && nc_check_remote_conn $clusterip $nsvc
					nc_connect_back_from_remote_ip_port "$z" $clusterip $nsvc tcp
				done
			fi
			if [ -n "$node1svcportsudp" ];then
				for nsvc in ${node1svcportsudp};do
					clusterip=$(kubectl get svc -A|egrep ",?${nsvc}:.*\/UDP"|awk '{print $5}')
					#test ! -z "$clusterip" && nc_check_remote_conn $clusterip $nsvc
					nc_connect_back_from_remote_ip_port "$z" $clusterip $nsvc udp 10
				done
			fi
			nc_connect_back_from_remote_ip_port "$z" downloads.dell.com 443 tcp
			nc_connect_back_from_remote_ip_port "$z" downloads.linux.hpe.com 80 tcp
			nc_connect_back_from_remote_ip_port "$z" repo.metalsoft.io 80 tcp
			nc_connect_back_from_remote_ip_port "$z" registry.metalsoft.dev 443 tcp
			nc_connect_back_from_remote_ip_port "$z" quay.io 443 tcp
			nc_connect_back_from_remote_ip_port "$z" gcr.io 443 tcp
			nc_connect_back_from_remote_ip_port "$z" cloud.google.com 443 tcp
			nc_connect_back_from_remote_ip_port "$z" smtp.office365.com 587 tcp

			#agents to try to connect to oob box:
			if [ -n "$oobIp" ];then
				for o in ${oobIp};do

					if [ -n "$oob_tcp_ports" ];then
						for otp in $oob_tcp_ports;do
							nc_check_remote_conn $o "$otp"
						done
					fi
					if [ -n "$oob_udp_ports" ];then
						for oup in $oob_udp_ports;do
							nc_check_remote_conn $o "$oup" udp
						done
					fi

				done
			fi
		else
			echo ${lightred}Could not SSH into "$z" port $sshport to perform remote checks${nc}
		fi
	done
fi


if [ -n "$oobIp" ];then
	for z in ${oobIp};do

		if [ -n "$oob_tcp_ports" ];then
			for otp in $oob_tcp_ports;do
				nc_check_remote_conn "$z" "$otp"
			done
		fi
		if [ -n "$oob_udp_ports" ];then
			for oup in $oob_udp_ports;do
				nc_check_remote_conn "$z" "$oup" udp
			done
		fi

	done
fi

# vim: set ts=2 sts=2 sw=2 et autoindent:
