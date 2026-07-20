# MetalSoft for NVIDIA Spectrum-X: Air Lab Preparation

This guide covers the one-time preparation of an NVIDIA Air lab that runs the
MetalSoft controller on-premises and drives a Cumulus Linux Spectrum-X fabric. It is
written for the engineer who prepares the lab image and stores the checkpoint that the
per-topology demos start from. It also lists the short set of steps that have to be
repeated after every lab restart, which apply to anyone who launches the lab.

## What the prepared lab contains

The lab hosts a self-managed MetalSoft deployment alongside the fabric it manages:

| Component | Address | Role |
|---|---|---|
| Global Controller (GC) | `192.168.200.3` | MetalSoft control plane and UI (`demo.metalsoft.io`) |
| Site Controller (SC) | `192.168.200.2` | Site agent that reaches the switches |
| Jumpstation | `oob-mgmt-server` | Out-of-band host where all CLI and Terraform commands run |
| Leaf / spine / super-spine switches | `192.168.200.11` upward | Cumulus Linux 5.14.0 |
| HGX hosts | after the switches (topology dependent) | Ubuntu compute nodes with eight rail NICs each |

Once preparation is complete and the checkpoint is stored, the following are already
in place, so the demos begin at fabric creation:

- `metalcloud-cli`, `jq`, `ansible`, and `sshpass` installed on the jumpstation.
- The MetalSoft API endpoint and key loaded into the jumpstation shell.
- The MetalSoft CA certificate trusted by the jumpstation.
- The `wait_for_job_group` helper defined in the shell profile.
- The Cumulus 5.14 configuration templates, the per-topology YAML files, and the
  Terraform manifests staged under `~/nvidia`.

## Prerequisites

- An NVIDIA Air lab imported from a MetalSoft Spectrum-X topology, with the GC and SC
  virtual machines present and the switches booted on Cumulus Linux 5.14.0.
- Administrative access to the GC (`192.168.200.3`) and the SC (`192.168.200.2`).
- The switch management password for the lab.

## Part 1: Expose the MetalSoft controller

The controller listens inside the lab on `192.168.200.3`. These steps make it
reachable from the jumpstation and, for the web UI, from your workstation.

### 1.1 Forward the controller port on the jumpstation

On `oob-mgmt-server`, enable forwarding and redirect inbound HTTPS to the controller:

```bash
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A PREROUTING  -i eth0 -p tcp --dport 443 -j DNAT --to 192.168.200.3:443
sudo iptables -t nat -A POSTROUTING -p tcp -d 192.168.200.3 --dport 443 -j MASQUERADE
```

These rules are held in memory and do not survive a restart. They are repeated in the
per-restart section below.

### 1.2 Publish an HTTPS service in NVIDIA Air

In the Air interface, create a service on the jumpstation:

- Service Name: `HTTPS`
- Interface: `oob-mgmt-server:eth0`
- Service Type: `HTTPS`
- Service Port: `443`

Air returns an external host name and an external port, for example
`worker-8f961120.dsx-air.nvidia.com` and `24371`. Record both. Air assigns a new
external port each time the lab restarts.

### 1.3 Resolve `demo.metalsoft.io`

On the SC (`192.168.200.2`), add the controller name to `/etc/hosts` and restart the
application containers:

```
192.168.200.3 demo.metalsoft.io
```

```bash
dcrestart
```

On the workstation you use for the web UI, map `demo.metalsoft.io` to the external
host address from step 1.2 in your local `/etc/hosts`, and trust the MetalSoft CA
certificate there as well. It is the same certificate installed on the jumpstation in
step 2.3 (`/usr/local/share/ca-certificates/metalsoft_ca.crt`); import it into your
workstation's browser or OS trust store so the UI loads without a certificate warning
(or accept the self-signed-certificate warning in the browser to proceed).

### 1.4 Set the controller UI port

On the GC, point the UI at the external port returned in step 1.2:

```bash
nvidia-ms-helper 24371
```

The port changes on every restart, so this command is repeated after each launch.

## Part 2: Install the jumpstation toolkit

Run these steps once on `oob-mgmt-server`.

### 2.1 Packages

```bash
wget -O- https://apt.releases.hashicorp.com/gpg | gpg --dearmor | sudo tee /usr/share/keyrings/hashicorp-archive-keyring.gpg > /dev/null

echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(grep -oP '(?<=UBUNTU_CODENAME=).*' /etc/os-release || lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list

sudo apt update && sudo apt install -y ansible sshpass jq terraform
```

### 2.2 The MetalSoft CLI

```bash
curl -skL "$(curl -s https://api.github.com/repos/metalsoft-io/metalcloud-cli/releases/latest \
    | grep -i browser_download_url | grep "$(dpkg --print-architecture)" | grep deb \
    | head -n1 | cut -d'"' -f4)" -o metalcloud-cli.deb
sudo dpkg -i metalcloud-cli.deb
metalcloud-cli completion bash | sudo tee /etc/bash_completion.d/metalcloud-cli >/dev/null
```

### 2.3 API credentials and controller trust

Copy the API endpoint and key from the GC, resolve the controller name locally, and
install the MetalSoft CA so that TLS validates:

```bash
ssh -n root@192.168.200.3 'grep METALCLOUD /root/.bashrc' | tee -a ~/.bashrc
echo "192.168.200.3 demo.metalsoft.io" | sudo tee -a /etc/hosts
source ~/.bashrc
test -n "$METALCLOUD_API_KEY" && echo "export TF_VAR_api_key='$METALCLOUD_API_KEY'" >> ~/.bashrc
test -n "$METALCLOUD_ENDPOINT" && echo "export TF_VAR_endpoint='$METALCLOUD_ENDPOINT'" >> ~/.bashrc
echo "export TF_VAR_site='dc-demo'" >> ~/.bashrc

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
sudo update-ca-certificates
```

### 2.4 Deploy-wait helper

Fabric deploys are asynchronous. The following helper blocks until a deploy's job
group has finished and then prints the status of each job. Add it to the shell
profile so every demo can call it:

```bash
cat <<'EOFF' >> ~/.bashrc

wait_for_job_group() {
  local jg="$1"
  local sleep_time="${2:-15}"
  test -z "$jg" && echo "Job Group not specified" && return 1
  echo "waiting for job group $jg to finish ..."
  until [ -n "$(metalcloud-cli job-group get "$jg" -f json | jq -r '.finishedTimestamp // empty')" ]; do
    metalcloud-cli job list --filter-job-group-id "$jg" -f json \
      | jq -r 'group_by(.status)[] | "\(length)\t\(.[0].status)"'
    sleep "$sleep_time"
  done
  echo "job group $jg finished - per-job status:"
  metalcloud-cli job list --filter-job-group-id "$jg"
}
EOFF
source ~/.bashrc
```

## Part 3: Stage the demo assets

Place the repository contents on the jumpstation under `~/nvidia`. Each topology draws
from the same set of files:

```bash
mkdir -p ~/nvidia && cd ~/nvidia
# copy from this repository:
#   cumulus-5.14-templates/     the five Cumulus 5.14 configuration templates
#   ethernet-fabric.<topology>.yaml   the fabric definition (sets the library label)
#   oob-subnet.<topology>.yaml  the out-of-band management subnet
#   switches.<topology>.yaml    the switch inventory for the topology
#   fabric-config.<topology>.l3evpn.yaml   the fabric build definition
#   endpoints.<topology>.yaml   the HGX endpoint definitions
#   route-domain.<topology>.yaml   the tenant VRF (route domain)
#   l3-profile.<topology>.yaml  the L3-only logical network profile
#   netplan/<topology>/         the per-host HGX rail netplan files
#   terraform/nvidia-spectrumx-<topology>.tf   the tenant onboarding manifest
```

In each `switches.<topology>.yaml`, set `managementPassword` to the lab's switch
password in place of the `${SWITCH_PASSWORD}` placeholder.

## Part 4: Store the checkpoint

With Parts 1 through 3 complete, confirm the environment (see below), then stop the
lab in NVIDIA Air using **Store Checkpoint**. The stored image carries the toolkit,
the trusted controller, and the staged assets, so the published demos begin at fabric
creation.

## After each lab restart

NVIDIA Air does not persist the NAT rules or the external service port across a
restart. After the lab resumes, repeat the following:

1. Re-apply the port-forward rules from Part 1.1 on `oob-mgmt-server`.
2. Read the new external host and port from the Air HTTPS service (Part 1.2).
3. Update `demo.metalsoft.io` in your workstation `/etc/hosts` to the new external
   address.
4. Set the controller UI port to the new value on the GC:

   ```
   nvidia-ms-helper <new-port>
   ```

## Verifying the environment

From the jumpstation:

```bash
metalcloud-cli fabric list                 # the CLI reaches the controller
metalcloud-cli site list                   # the lab site is present
```

If both commands return without a TLS or authentication error, the toolkit and
controller trust are in place and the lab is ready for a demo.
