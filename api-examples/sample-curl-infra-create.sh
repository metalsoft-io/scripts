#!/bin/bash

#Sample CURL-based script to create a simple infrastructure with a server and a logical network
#METALCLOUD_API_KEY and METALCLOUD_ENDPOINT environment variables need to be set

if [ -z "$METALCLOUD_API_KEY" ]; then
  echo "Error: METALCLOUD_API_KEY environment variable is not set."
  exit 1
fi

if [ -z "$METALCLOUD_ENDPOINT" ]; then
  echo "Error: METALCLOUD_ENDPOINT environment variable is not set."
  exit 1
fi

API_URL=$METALCLOUD_ENDPOINT/api/v2
API_TOKEN=$METALCLOUD_API_KEY

SITE_ID="us02-chi-qts01-dc"
SERVER_TYPE="M.4.8.1.v2"
NETWORK_PROFILE_LABEL="wan-profile"

RANDOM_STRING=$(openssl rand -hex 8)

INFRA_LABEL="infra-$RANDOM_STRING"


PRIVATE_LOGICAL_NETWORK_LABEL="test-vlan1-private-$RANDOM_STRING"


#get list of sites
sites=$(curl --no-progress-meter -X GET "$API_URL/sites" \
    -H "Authorization: Bearer $API_TOKEN" \
    -H "Content-Type: application/json")

SITE_ID=$(echo $sites | jq ".data[0] | select(.slug== \"$SITE_ID\").id")

#echo "Site id is $SITE_ID"

#get list of server types
server_types=$(curl --no-progress-meter -X GET "$API_URL/server-types" \
    -H "Authorization: Bearer $API_TOKEN" \
    -H "Content-Type: application/json")

SERVER_TYPE_ID=$(echo $server_types | jq ".data[0] | select(.name== \"$SERVER_TYPE\").id")

#echo "Server type id is $SERVER_TYPE_ID"


#create infra in the first site
INFRA=$(curl --no-progress-meter -X POST "$API_URL/infrastructures" \
    -H "Authorization: Bearer $API_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{
        \"label\": \"$INFRA_LABEL\",
        \"siteId\": $SITE_ID
    }")

INFRA_ID=$(echo $INFRA | jq ".id")

#get list of infras to identify the ID (could be done prior but as to not re-fetch)
infras=$(curl --no-progress-meter -X GET "$API_URL/infrastructures" \
    -H "Authorization: Bearer $API_TOKEN" \
    -H "Content-Type: application/json")

INFRA_ID=$(echo $infras | jq ".data[] | select(.label== \"$INFRA_LABEL\").id")

echo "Infra id is $INFRA_ID"

#create server group in the first site
sig=$(curl --no-progress-meter -X POST "$API_URL/infrastructures/$INFRA_ID/server-instance-groups" \
    -H "Authorization: Bearer $API_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{
        \"label\": \"my-srv-01\",
        \"serverGroupName\": \"my-srv-01\",
        \"instanceCount\": 1,
        \"defaultServerTypeId\": $SERVER_TYPE_ID
    }")


SERVER_INSTANCE_GROUP_ID=$(echo $sig | jq ".id")
echo "server instance group is $SERVER_INSTANCE_GROUP_ID"


# Get list of network profiles
network_profiles=$(curl --no-progress-meter -X GET "$API_URL/logical-network-profiles" \
    -H "Authorization: Bearer $API_TOKEN" \
    -H "Content-Type: application/json")

#echo $network_profiles
NETWORK_PROFILE_ID=$(echo $network_profiles | jq ".data[] | select(.name==\"$NETWORK_PROFILE_LABEL\") | .id")

echo "Network profile id is $NETWORK_PROFILE_ID"

#create logical network from a network profile
logical_network=$(curl --no-progress-meter -X POST "$API_URL/logical-networks/actions/create-from-profile" \
    -H "Authorization: Bearer $API_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{
        \"label\": \"$PRIVATE_LOGICAL_NETWORK_LABEL\",
        \"logicalNetworkProfileId\": $NETWORK_PROFILE_ID,
        \"infrastructureId\": $INFRA_ID
    }")

#echo "Logical network creation response: $logical_network"
LOGICAL_NETWORK_ID=$(echo $logical_network | jq ".id")

echo "Logical network id is $LOGICAL_NETWORK_ID"


#create logical network attachment of existing network
connection=$(curl --no-progress-meter -X POST "$API_URL/server-instance-groups/$SERVER_INSTANCE_GROUP_ID/config/networking/connections" \
    -H "Authorization: Bearer $API_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{
        \"logicalNetworkId\": \"$LOGICAL_NETWORK_ID\",
        \"tagged\": false,
        \"accessMode\": \"l2\",
        \"mtu\": 1500,
        \"providesDefaultRoute\": false,
        \"redundancy\": {
                    \"mode\": \"active-active\",
                    \"implementation\": {
                        \"implementationType\": \"link-aggregation\"
                    }
                }
        }")

#echo "Connection response: $connection"
echo "all done, deploying"


deploy_response=$(curl --no-progress-meter -X POST "$API_URL/infrastructures/$INFRA_ID/actions/deploy" \
    -H "Authorization: Bearer $API_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{
        \"allowDataLoss\": false,
        \"shutdownOptions\": {
            \"attemptSoftShutdown\": true,
            \"softShutdownTimeout\": 0,
            \"attemptHardShutdown\": true,
            \"forceShutdown\": true
        },
        \"serverTypeIdToPreferredServerIds\": {}
    }")

echo "Deploy response: $deploy_response"
