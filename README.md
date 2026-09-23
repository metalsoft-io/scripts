
# Metalsoft Scripts


## Example of running the Agents install script

```bash
IMAGES_TAG=v7.4.0 \
SSL_HOSTNAME=yourhost.metalsoft.io \
DATACENTERNAME=your-datacenter-id \
MS_TUNNEL_SECRET=agentSecretFromController \
REGISTRY_LOGIN=base64HashOfRegistryCredentials \
SSL_B64=base64OfSslKeyAndCertPemFormat [ or SSL_PULL_URL=https://url.to/ssl.pem ] \
[ ACAP_ANSIBLE_RUNNER=1 ACAP_BUILD_IMAGE=1 ... ] \
bash <(curl -sk https://raw.githubusercontent.com/metalsoft-io/scripts/main/deploy-agents.sh)
```
