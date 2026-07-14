<!-- AIR:tour -->

# Metalsoft GlobalController+Sitecontroller setup

This environment demonstrates the setup and use of Metalsoft's GlobalController (GC) and SiteController (SC)

## Demo topology

gc = Global Controller VM

sc = Site Controller VM

oob-mgmt-server = OOB Management Server VM, also the jumpbox through which the gc and sc VMs are accessed

<!-- AIR:page -->

## Demo setup

All environment devices access are done via the jump server - `oob-mgmt-server`.

Use the default access credentials to login the `oob-mgmt-server`:
 - Username: ***ubuntu***
 - Password: ***nvidia***

Once the Environment is initially started, the VMs will need few minutes to be up and accessible.

From the  `oob-mgmt-server`:

GC should be accessible via `ssh -l root 192.168.200.3`
Password: `MetalsoftR0cks@$@$`

SC should be accessible via `ssh -l root 192.168.200.2`
Password: `MetalsoftR0cks@$@$`

<!-- AIR:page -->

## Setup GC UI to be accessed from outside:

On `oob-mgmt-server`, execute the following commands to setup the forwarding of port 443 towards the GC:

```bash
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination 192.168.200.3:443
sudo iptables -t nat -A POSTROUTING -p tcp -d 192.168.200.3 --dport 443 -j MASQUERADE
```

where `192.168.200.3` is the IP address of the GC

Within Nvidia Air in the Simulation under Services tab, you will find HTTPS service with:
- a custom Port (ex: 12345)
- a hostname (ex: worker-8f961120.dsx-air.nvidia.com)

Please resolve/ping the hostname, and make a note of the IP it resolves to.

Once the GC is accessible via `ssh -l root 192.168.200.3` execute the following command:

```bash
nvidia-ms-helper <custom_port>
```

where `<custom_port>` is the port you noted in the previous step

Then on your Local Workstation point in your `hosts` file:

```
<IP_of_worker_host> demo.metalsoft.io
```

Make sure that in Nvidia Air Simuiation, unser Services tab a Service exists which creates HTTPS forwarding:

- Service name: `HTTPS`
- Service type: `HTTPS`
- Service port: `443`

Now you should be able to access the Metalsoft UI via `https://demo.metalsoft.io:<custom_port>/`

Initial admin login:
User: `demo@metalsoft.io`
Password: `MetalsoftR0cks@$@$`


<!-- AIR:page -->

## Setup SC to connect to GC:

On SC make sure that the following entry exists within `/etc/hosts` file:

```bash
192.168.200.3 demo.metalsoft.io
```

Once applied, run the following command to restart the docker containers so they make use of the setting:

```bash
dcrestart
```

## Troubleshooting GC:

once you ssh into the GC, you can check if all k8s pods are running via: `kw` (alias for: kubectl watch)

If all pods are not in `Running` state, and they do not auto-recover, you can force-restart with `k-restart-all -A`

---

When accessing the URL: `https://demo.metalsoft.io:<custom_port>/`, Since the Demo is using a self-signed SSL,

you will have to import the following CA certificate to the workstation from which you are accessing the URL:

```
-----BEGIN CERTIFICATE-----
MIIEBzCCAu+gAwIBAgIUHKD6RcgrIEoHCNHErJUfUwDJMCAwDQYJKoZIhvcNAQEL
BQAwgZIxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJJTDEQMA4GA1UEBwwHQ2hpY2Fn
bzEcMBoGA1UECgwTTWV0YWxzb2Z0IENsb3VkIEluYzELMAkGA1UECwwCSVQxFTAT
BgNVBAMMDG1ldGFsc29mdC5pbzEiMCAGCSqGSIb3DQEJARYTc3lzb3BzQG1ldGFs
c29mdC5pbzAeFw0yNjA1MjAxMjMwNDZaFw0zNjA1MTcxMjMwNDZaMIGSMQswCQYD
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
DQEBCwUAA4IBAQAFarlYcAT/I/ybC8ywOiuOVOOVi7YBqz+j9HwKB/s36ViZEmsZ
/SNiGBrzDEE5kCLfzxS7XLtiet7zYCU+fxezePdt3gNpyjLpibZKvkb1LxfG3EKK
+HEg0+hoMCJG8WNeVEGoa1rNUgXk9FT57hV1mquymzhTcXtXeXGWEakbHSs5Oj3u
aQmS/TaU4iCyWrbB9EISr6irIG3Y7GS2Vv2/cyll1XVfrWYBzq1cg0RIJc0WIYoN
ZqUyUBGgaH/f2Kp4oM44YCLumqKSxT8goHwGtjZ+LTYhW/9NvL0L9Sv5HzG2yEEJ
HTAjPGqtBmfrA3e6HutGyfEeL8R2SUX+Z+Xy
-----END CERTIFICATE-----
```


## Troubleshooting SC:

once you ssh into the SC, you can check the running containers via: `docker ps`

```bash
# docker ps
CONTAINER ID   IMAGE                                       COMMAND                  CREATED        STATUS        PORTS     NAMES
0c55d6012c96   registry.metalsoft.dev/sc/nfs-server:3      "/usr/local/bin/entr…"   45 hours ago   Up 45 hours             nfs-server
95e0116a9158   registry.metalsoft.dev/sc/ms-agent:v7.4.0   "/entrypoint.sh"         45 hours ago   Up 45 hours             ms-agent
```
and further check the logs for `ms-agent` with:

```bash
docker logs -f ms-agent
```

If you need to examine the current `docker compose` setup:

```bash
SC: dc-demo agent-demo ~ # cd /opt/metalsoft/agents/
SC: dc-demo agent-demo agents # ls -la
total 24
drwxr-xr-x 2 root root 4096 Jul  8 11:50 .
drwxr-xr-x 8 root root 4096 Jul  6 13:48 ..
-rw-r--r-- 1 root root   11 Jul  8 09:03 .env
-rw-r--r-- 1 root root 4486 Jul  6 14:22 docker-compose.yaml
-rw-r--r-- 1 root root 3246 Jul  6 13:49 ssl-cert.pem
```

## If you need to install and use `metalcloud-cli` on the `oob-mgmt-server`:

```bash
# Install metalcloud-cli
curl -skL $(curl -s https://api.github.com/repos/metalsoft-io/metalcloud-cli/releases/latest | grep -i browser_download_url  | grep "$(dpkg --print-architecture)" | grep deb | head -n 1 | cut -d'"' -f4) -o metalcloud-cli.deb && sudo dpkg -i metalcloud-cli.deb && metalcloud-cli completion bash |sudo tee /etc/bash_completion.d/metalcloud-cli

# Get the METALCLOUD environment variables from GC and add them locally
ssh root@192.168.200.3 'grep METALCLOUD /root/.bashrc' | tee -a ~/.bashrc

# Add the demo.metalsoft.io host to /etc/hosts
echo "192.168.200.3 demo.metalsoft.io"|sudo tee -a /etc/hosts

# Add the Metalsoft CA cert to /usr/local/share/ca-certificates
sudo tee /usr/local/share/ca-certificates/metalsoft_ca.crt >/dev/null << 'ENDD'
-----BEGIN CERTIFICATE-----
MIIEBzCCAu+gAwIBAgIUHKD6RcgrIEoHCNHErJUfUwDJMCAwDQYJKoZIhvcNAQEL
BQAwgZIxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJJTDEQMA4GA1UEBwwHQ2hpY2Fn
bzEcMBoGA1UECgwTTWV0YWxzb2Z0IENsb3VkIEluYzELMAkGA1UECwwCSVQxFTAT
BgNVBAMMDG1ldGFsc29mdC5pbzEiMCAGCSqGSIb3DQEJARYTc3lzb3BzQG1ldGFs
c29mdC5pbzAeFw0yNjA1MjAxMjMwNDZaFw0zNjA1MTcxMjMwNDZaMIGSMQswCQYD
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
DQEBCwUAA4IBAQAFarlYcAT/I/ybC8ywOiuOVOOVi7YBqz+j9HwKB/s36ViZEmsZ
/SNiGBrzDEE5kCLfzxS7XLtiet7zYCU+fxezePdt3gNpyjLpibZKvkb1LxfG3EKK
+HEg0+hoMCJG8WNeVEGoa1rNUgXk9FT57hV1mquymzhTcXtXeXGWEakbHSs5Oj3u
aQmS/TaU4iCyWrbB9EISr6irIG3Y7GS2Vv2/cyll1XVfrWYBzq1cg0RIJc0WIYoN
ZqUyUBGgaH/f2Kp4oM44YCLumqKSxT8goHwGtjZ+LTYhW/9NvL0L9Sv5HzG2yEEJ
HTAjPGqtBmfrA3e6HutGyfEeL8R2SUX+Z+Xy
-----END CERTIFICATE-----
ENDD

# Update CAs
sudo update-ca-certificates

# add the wait function in bash:
cat <<'EOFF' >> ~/.bashrc

wait_for_job_group() {
  local jg="$1"
  local sleep_time="${2:-15}"
  test -z "$jg" && echo "Job Group not specified" && return 1
  echo "waiting for job group $jg to finish ..."
  # the group sets finishedTimestamp only once every job in it is terminal
  until [ -n "$(metalcloud-cli job-group get "$jg" -f json | jq -r '.finishedTimestamp // empty')" ]; do
    # progress: a count per status (e.g. "4 running", "2 returned_success")
    metalcloud-cli job list --filter-job-group-id "$jg" -f json \
      | jq -r 'group_by(.status)[] | "\(length)\t\(.[0].status)"'
    sleep "$sleep_time"
done
  echo "job group $jg finished - per-job status:"
  # every job should read returned_success / finished; anything else is a failure
  metalcloud-cli job list --filter-job-group-id "$jg"
}
EOFF

# source the bashrc
source ~/.bashrc

```

<!-- AIR:tour -->
