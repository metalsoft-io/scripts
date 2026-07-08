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

## Setup GC to be accessed from outside:

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

Now you should be able to access the Metalsoft UI via `https://demo.metalsoft.io:<custom_port>/`

Initial admin login:
User: `demo@metalsoft.io`
Password: `MetalsoftR0cks@$@$`


<!-- AIR:page -->

## Troubleshooting GC:

once you ssh into the GC, you can check if all k8s pods are running via: `kw` (alias for: kubectl watch)
If all pods are not in `Running` state, and they do not auto-recover, you can force-restart with `k-restart-all -A`

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

<!-- AIR:tour -->
