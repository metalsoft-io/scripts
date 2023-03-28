
# Metalsoft Scripts


## Example of running the Agents install script

```bash
NONINTERACTIVE_MODE=1 \
REGISTRY_LOGIN=base64HashOfRegistryCredentials \
DCCONF="https://config_url_copied_from_datacenter_page" \ 
SSL_B64=base64OfSslKeyAndCertPemFormat [ or SSL_PULL_URL=https://url.to/ssl.pem ] \
GUACAMOLE_KEY=undefined \ 
WEBSOCKET_TUNNEL_SECRET=undefined \
bash <(curl -sk https://raw.githubusercontent.com/metalsoft-io/scripts/main/deploy-agents.sh)
```
