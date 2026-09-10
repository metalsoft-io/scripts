
# Metalsoft Scripts


## Example of running the Agents install script

```bash
NONINTERACTIVE_MODE=1 \
REGISTRY_LOGIN=base64HashOfRegistryCredentials \
DCCONF="https://config_url_copied_from_datacenter_page" \ 
SSL_B64=base64OfSslKeyAndCertPemFormat [ or SSL_PULL_URL=https://url.to/ssl.pem ] \
bash <(curl -sk https://raw.githubusercontent.com/metalsoft-io/scripts/main/deploy-agents.sh)
```

## Site controller metrics (Prometheus)

`deploy-agents.sh` can ship the site controller's `ms-agent` metrics to a central
Prometheus. It is off by default. When enabled the script:

- sets `ENABLE_METRICS=true` on the `ms-agent` container, which makes the agent serve
  Prometheus metrics on port `9464` (`/metrics`); the default is `false` and the port
  stays closed,
- adds a `vmagent` container to `/opt/metalsoft/agents/docker-compose.yaml` that
  scrapes `127.0.0.1:9464` every 30 s and **pushes** the samples with Prometheus
  `remote_write` over HTTPS + basic auth. Push, not pull: site controllers are usually
  behind NAT and only open outbound connections, like the agent's own tunnel to the
  controller. While the receiver is unreachable, samples are buffered on disk (up to
  1 GB) and replayed afterwards,
- writes the scrape config and the credentials (mode 0600) to
  `/opt/metalsoft/agents/vmagent/`.

The receiving Prometheus must have its remote_write receiver enabled and exposed
behind authentication (for kube-prometheus-stack: `enableRemoteWriteReceiver: true`
plus an ingress route for `/api/v1/write` with a basic-auth middleware). One
basic-auth user per site controller is recommended.

### Example

Run the install script exactly as you normally do and add the metrics variables:

```bash
ENVVAR_ENABLE_METRICS=enabled \
METRICS_REMOTE_WRITE_URL=https://grafana.example.com/api/v1/write \
METRICS_REMOTE_WRITE_USERNAME=sc-mydc-01 \
METRICS_REMOTE_WRITE_PASSWORD='<password>' \
METRICS_GC_NAMESPACE=mycompany-metalcloud \
DOCKERENV=1 IMAGES_TAG=v8.0.0 DATACENTERNAME=mydc SSL_HOSTNAME=controller.example.com \
REGISTRY_LOGIN=base64HashOfRegistryCredentials SSL_B64=base64OfSslKeyAndCertPemFormat \
ACAP_OOB_HTTP_PROXY=1 ACAP_FILE_TRANSFER=1 ACAP_COMMAND_EXECUTION=1 ACAP_NETCONF=1 \
bash <(curl -sk https://raw.githubusercontent.com/metalsoft-io/scripts/main/deploy-agents.sh)
```

`ACAP_ENABLE_METRICS=1` is accepted as an alias of `ENVVAR_ENABLE_METRICS=enabled`,
like the other capabilities.

### Variables

| Variable | Required | Description |
|---|---|---|
| `ENVVAR_ENABLE_METRICS` | yes | `enabled` turns the feature on (default `disabled`) |
| `METRICS_REMOTE_WRITE_URL` | yes | remote_write receiver, e.g. `https://<host>/api/v1/write` |
| `METRICS_REMOTE_WRITE_USERNAME` | yes | basic-auth user configured on the receiver |
| `METRICS_REMOTE_WRITE_PASSWORD` | yes | its password; stored in `/opt/metalsoft/agents/vmagent/secrets/password` |
| `METRICS_GC_NAMESPACE` | yes | Kubernetes namespace of the Global Controller environment this site controller belongs to (e.g. `mycompany-metalcloud`). Becomes the `namespace` label, so the site controller shows up next to the controller's own services in the MetalSoft Grafana dashboards |
| `METRICS_SC_NAME` | no | name of this site controller in Prometheus (`pod`, `instance`, `site_controller` labels). Default `<DATACENTERNAME>-<ip with dashes>`, stable across re-runs |
| `METRICS_SCRAPE_INTERVAL` | no | default `30s` |
| `METRICS_REMOTE_WRITE_CA_FILE` | no | CA bundle for the receiver's certificate, path inside the container (the host's `/etc/ssl/certs` is mounted there). Default: system trust store, which already contains the MetalSoft CA |
| `METRICS_REMOTE_WRITE_INSECURE` | no | `1` skips TLS verification of the receiver (not recommended) |
| `VMAGENT_URL` | no | vmagent image; default `<registry>/hub_docker_com/victoriametrics/vmagent:v1.149.0` |

If `ENVVAR_ENABLE_METRICS=enabled` is set but one of the required variables is
missing, the script prints an error, keeps `ENABLE_METRICS=false` and deploys the
site controller without the pusher.

### Check that it works

On the site controller:

```bash
docker ps --filter name=vmagent                     # Up
docker logs ms-agent 2>&1 | grep "metrics listener"  # "starting metrics listener on :9464/metrics"
docker logs vmagent --since 5m                       # no "cannot send" / 401 / x509 lines
curl -s 127.0.0.1:8429/metrics | grep -E '^vmagent_remotewrite_(requests_total|packets_dropped_total|pending_data_bytes)'
```

`vmagent_remotewrite_requests_total{status_code="2XX"}` must keep increasing and
`packets_dropped_total` stay at 0. On the Prometheus side:

```promql
up{job="site-controller", namespace="mycompany-metalcloud"}
build_info{app="agent", pod="mydc-10-0-0-5"}
```

### Disable again / rotate the password

Re-run the script without `ENVVAR_ENABLE_METRICS` (or with `disabled`): the agent
goes back to `ENABLE_METRICS=false` and the `vmagent` container is removed
(`docker compose up --remove-orphans`). To rotate the password, update it on the
receiver and re-run the script with the new `METRICS_REMOTE_WRITE_PASSWORD`.
