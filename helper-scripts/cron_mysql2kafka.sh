#!/bin/bash
# Author: Ron <ron.z@metalsoft.io>

# set in cron like:
# */5 * * * * ~/cron_mysql2kafka.sh <NAMESPACE> >> ~/cron_mysql2kafka.log 2>&1

namespace="$1"
test -z "$namespace" && test -n "$ns" && namespace="$ns"
test -z "$namespace" && echo "Namespace not specified as first parameter. Exiting.." && exit 2
k="kubectl -n $namespace"
nsexists="$($k get ns --no-headers|awk '{print $1}'|grep "^$namespace$")"
test -n "$nsexists" || { echo "Namespace: $namespace was not found. Exiting"; exit 3; }

dbname="$($k exec deploy/mysql -- mysql -BNe 'show databases' 2>/dev/null|grep -E '^metalsoft'|head -1|xargs|tr -d '\r')"
test -z "$dbname" && dbname="$($k exec deploy/mysql -- mysql -BNe 'show databases' 2>/dev/null|grep -E '^bsi_api_'|head -1)"
test -z "$dbname" && echo DBname not found. Exiting.. && exit 1

lastId="$($k exec deploy/kafka -- kafka-console-consumer --bootstrap-server broker:29092 --topic events_last_id --from-beginning --timeout-ms 10000 2>/dev/null|tail -1 || true)"
test -z "$lastId" && lastId=0

currentBatch="$($k exec deploy/mysql -- mysqlsh --result-format='json/raw' --sql --uri root@localhost --mysql --password= -D ${dbname} -e "select * from events where event_id > ${lastId}" 2>/dev/null)"
getLastId=$(echo "$currentBatch"|tail -1|grep -Po 'event_id":\d+'|cut -d: -f2)

test -n "$currentBatch" && echo "$currentBatch" | $k exec -i deploy/kafka -- kafka-console-producer --bootstrap-server broker:29092 --topic events &>/dev/null
test -n "$getLastId" && echo $getLastId| $k exec -i deploy/kafka -- kafka-console-producer --bootstrap-server broker:29092 --topic events_last_id &>/dev/null
