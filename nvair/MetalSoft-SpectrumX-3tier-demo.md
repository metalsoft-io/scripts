# MetalSoft for NVIDIA Spectrum-X: 3-Tier Demo (512 GPU)

This demo builds a three-tier Spectrum-X fabric from a clean state and attaches a
tenant to it, using the MetalSoft CLI and Terraform. The fabric spans two PODs joined
by a super-spine tier and runs EVPN over eBGP on Cumulus Linux 5.14.0. Its
distinguishing behaviour is inter-POD reachability: a host in one POD reaches a host in
the other across the super-spine tier. Allow about 50 minutes end to end; most of that
is switch deployment time.

## Before you begin

The lab was launched from the MetalSoft Spectrum-X checkpoint, and the per-restart steps
in the lab preparation guide have been applied. To understand or rebuild that setup, see
`MetalSoft-SpectrumX-initial-air-setup.md`.

### The lab environment

MetalSoft runs its controller inside the lab and manages the fabric centrally. You
describe the fabric and the tenant with `metalcloud-cli` on the jumpstation, and the
controller renders the Cumulus configuration and pushes it to every switch; you never log
in to a switch to configure it by hand. The lab is made up of these parts:

| Component | Address | Role |
|---|---|---|
| Jumpstation (`oob-mgmt-server`) | external SSH (see below) | Where you run every command in this demo |
| Global Controller (GC) | `192.168.200.3` | MetalSoft control plane and web UI |
| Site Controller (SC) | `192.168.200.2` | Site agent that reaches and configures the switches |
| Leaf, spine, and super-spine switches | `192.168.200.11` and up | Cumulus Linux 5.14.0 |
| HGX hosts | `192.168.200.31` to `.38` | Ubuntu compute nodes, eight rail NICs each |

**Run every command in this demo on the `oob-mgmt-server` jumpstation.** The Global and
Site Controllers do their own work; you do not run the demo steps on them. The only time
you log in to the GC or SC directly is the Troubleshooting section at the end of this
guide.

Use these credentials for the lab:

| Target | How to reach it | Username | Password |
|---|---|---|---|
| Jumpstation (`oob-mgmt-server`) | Air console, then SSH | `ubuntu` | `nvidia` |
| Global Controller | `ssh -l root 192.168.200.3` | `root` | `MetalsoftR0cks@$@$` |
| Site Controller | `ssh -l root 192.168.200.2` | `root` | `MetalsoftR0cks@$@$` |
| MetalSoft web UI | `https://demo.metalsoft.io` | `demo@metalsoft.io` | `MetalsoftR0cks@$@$` |
| Switches | `ssh cumulus@<switch-ip>` | `cumulus` | set in `switches.3tier.yaml` |
| HGX hosts | `ssh ubuntu@<host-ip>` | `ubuntu` | `nvidia` |

### Reach the jumpstation over SSH

Before you can run anything, you need SSH access to the `oob-mgmt-server` jumpstation. A
freshly launched lab accepts key-based SSH only, never a password, and does not expose SSH
to the outside yet, so you cannot connect with `ssh` straight away (an early attempt fails
with `Permission denied (publickey)`).

**First, open the jumpstation console inside NVIDIA Air.** In the Air interface, open the
**Nodes** tab (or the topology view) and **double-click the `oob-mgmt-server` node** to
open its console in the browser. Log in at the console with the default credentials
`ubuntu` / `nvidia`. Use **Google Chrome**; the Air console does not work in Safari.

**Then install your public key** from that console, so your workstation can SSH in:

```bash
mkdir -p ~/.ssh && chmod 700 ~/.ssh
echo 'ssh-ed25519 AAAA...replace-with-your-public-key... you@workstation' >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

**Finally, publish an SSH service** so the jumpstation is reachable from outside. In the
Air interface, add a service on the jumpstation:

- Service Name: `SSH`
- Interface: `oob-mgmt-server:eth0`
- Service Type: `SSH`
- Service Port: `22`

Air returns an external host name and port for the service. You can now reach the
jumpstation over SSH at that host and port. Connect to it as `ubuntu` and work in
`~/nvidia`, where the configuration templates, the topology YAML files, and the Terraform
manifests are already staged:

```
ubuntu@oob-mgmt-server:~$ cd nvidia/
ubuntu@oob-mgmt-server:~/nvidia$ ls
cumulus-5.14-templates  ethernet-fabric.3tier.yaml       l3-profile.3tier.yaml  oob-subnet.3tier.yaml    switches.3tier.yaml
endpoints.3tier.yaml    fabric-config.3tier.l3evpn.yaml  netplan                route-domain.3tier.yaml  terraform
ubuntu@oob-mgmt-server:~/nvidia$
```

The switch password has been set in `switches.3tier.yaml`.

### Confirm the controller is reachable

The environment table above lists the two controller VMs. Confirm both answer from the
jumpstation before you start:

```bash
ping -c3 192.168.200.3    # Global Controller
ping -c3 192.168.200.2    # Site Controller
```

If either address does not answer, the virtual machine most likely did not receive a DHCP
lease when the lab started. Stop the lab in NVIDIA Air, start it again, and re-check.

Then confirm the Site Controller has connected to the Global Controller:

```bash
metalcloud-cli site agents 1
```
Output similar to the following confirms that the Site Controller has connected to the Global Controller:

```
┌─────────────────────────────────────────────────┬────────────────────────────┬─────────┬────────────┬─────────┬───────────────────┬─────────────────────┐
│ ID                                              │ HOSTNAME                   │ SITE    │ AGENT TYPE │ VERSION │ IP                │ LAST SEEN           │
├─────────────────────────────────────────────────┼────────────────────────────┼─────────┼────────────┼─────────┼───────────────────┼─────────────────────┤
│ dc-demo-fd17-625c-f037-2-a00-27ff-fec9-ab57-05e │ ms-tunnel-6b4869d7d9-qk57x │ dc-demo │ ms-agent   │ v7.4.2  │ 10.42.0.152:34482 │ 16 Jul 26 14:50 UTC │
└─────────────────────────────────────────────────┴────────────────────────────┴─────────┴────────────┴─────────┴───────────────────┴─────────────────────┘
```

### Access the web UI (optional)

This demo runs entirely from the command line, so the web UI is optional. Open it if you
want to watch the fabric, the endpoints, and the tenant appear in the MetalSoft interface
as you build them. The UI runs on the Global Controller; the steps below expose it and
open it from your workstation.

On the jumpstation, forward the controller's HTTPS port. These rules are not persistent,
so re-apply them after every lab restart:

```bash
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A PREROUTING  -i eth0 -p tcp --dport 443 -j DNAT --to 192.168.200.3:443
sudo iptables -t nat -A POSTROUTING -p tcp -d 192.168.200.3 --dport 443 -j MASQUERADE
```

In NVIDIA Air, publish an HTTPS service on the jumpstation, the same way you added the SSH
service:

- Service Name: `HTTPS`
- Interface: `oob-mgmt-server:eth0`
- Service Type: `HTTPS`
- Service Port: `443`

Air returns an external host name and port for the service (for example
`worker-8f961120.dsx-air.nvidia.com` and `24371`). Note both; Air assigns a new external
port on each restart.

On the Global Controller, point the UI at that external port. Log in as `root`
(`ssh -l root 192.168.200.3`, password `MetalsoftR0cks@$@$`) and run it with the port Air
returned:

```bash
nvidia-ms-helper 24371
```

On your workstation, look up the external host's IP address (`ping` or `dig` the host name
Air returned), then map `demo.metalsoft.io` to it in your local `/etc/hosts`:

```
<external-host-ip> demo.metalsoft.io
```

The controller uses a self-signed certificate, so the browser warns about it. Either
accept the warning to continue, or trust the MetalSoft CA certificate on your workstation
(it is staged on the jumpstation at `/usr/local/share/ca-certificates/metalsoft_ca.crt`
and reproduced in `MetalSoft-SpectrumX-initial-air-setup.md`).

Open `https://demo.metalsoft.io:<external-port>/` in the browser, using the port from
above, and log in:

- Username: `demo@metalsoft.io`
- Password: `MetalsoftR0cks@$@$`

The port-forward, the Air service port, and `nvidia-ms-helper` all reset when the lab
restarts; the lab preparation guide collects these under "After each lab restart".

## What you will build

| Property | Value |
|---|---|
| Switches | 20 (8 leaf, 8 spine, 4 super-spine) |
| PODs | 2 (each POD is one scalable unit) |
| HGX hosts | 8 (512 GPUs) |
| Fabric label | `spectrumx-3tier-514` |
| Tenant | `tenant1`, one L3 EVPN network |
| NOS | Cumulus Linux 5.14.0 |

## Step 1: Create and activate the fabric

Create the fabric on the lab site, activate it, and create the out-of-band management
subnet the switches are addressed from.

```bash
metalcloud-cli fabric create 1 spectrumx-3tier-514 ethernet "Spectrum-X 3-tier (5.14)" \
        --config-source ethernet-fabric.3tier.yaml
```

```bash
metalcloud-cli fabric activate 1
```

```bash
metalcloud-cli subnet create --config-source oob-subnet.3tier.yaml
```

Keep the fabric label `spectrumx-3tier-514`. The Terraform manifest in Step 11
resolves the fabric by that label. The fabric is recognised as three-tier because its
inventory contains super-spine switches.

## Step 2: Import the switches

Set `fabricId` in `switches.3tier.yaml` to `1`, then import the twenty switches:

```bash
metalcloud-cli fabric import-devices 1 --config-source switches.3tier.yaml
```

## Step 3: Discover switch interfaces

The switch configuration in Step 4 works from each switch's discovered port
inventory. Trigger discovery across every switch; this may take a few minutes to
complete. Then confirm one switch reports interfaces:

```bash
for ID in $(metalcloud-cli fabric get-devices 1 -f json | jq -r '.[].id'); do
  metalcloud-cli network-device discover "$ID"
done
```

```bash
metalcloud-cli network-device get-ports 1     # returns a list of swpNsN ports
```

If the port list is empty, the switch is not reachable. Check the address and password
in `switches.3tier.yaml`.

The switches are imported and reachable, but MetalSoft has not configured them yet.
Each switch check in this demo runs against a single switch chosen by the `SW` variable
at the top of the block; change `SW` and re-run to inspect another switch. Each output
line is prefixed with the switch name in green, so it is clear which switch answered. The
switch hostnames for this topology are:

- Leaves: `leaf-pod00-su00-r0`, `leaf-pod00-su00-r1`, `leaf-pod00-su00-r2`, `leaf-pod00-su00-r3`, `leaf-pod01-su00-r0`, `leaf-pod01-su00-r1`, `leaf-pod01-su00-r2`, `leaf-pod01-su00-r3`
- Spines: `spine-pod00-r0-s00`, `spine-pod00-r1-s00`, `spine-pod00-r2-s00`, `spine-pod00-r3-s00`, `spine-pod01-r0-s00`, `spine-pod01-r1-s00`, `spine-pod01-r2-s00`, `spine-pod01-r3-s00`
- Super-spines: `ssp-group00-s00`, `ssp-group00-s01`, `ssp-group00-s02`, `ssp-group00-s03`

Log in as `cumulus` (the password is read from `switches.3tier.yaml`) and capture the
baseline, so the later steps have something to compare against:

```bash
# This block inspects one switch. The two awk lines resolve SW to its management IP and the
# cumulus password from the switch inventory; sshpass runs the commands below on the switch
# over SSH; the trailing awk prefixes each output line with the switch name in green. The
# commands that run on the switch are:
#     hostname                          (its configured hostname)
#     ip -br addr show lo               (loopback addresses)
#     sudo vtysh -c "show bgp summary"  (BGP neighbour table, from FRR)
SW=leaf-pod00-su00-r0    # switch to inspect; any hostname listed above, then re-run
SWIP=$(awk -v s="$SW" '$2=="identifierString:" && $3==s{f=1} f && $1=="managementAddress:"{print $2; exit}' ~/nvidia/switches.3tier.yaml)
SWPW=$(awk '/managementPassword:/{print $2; exit}' ~/nvidia/switches.3tier.yaml)
sshpass -p "$SWPW" ssh -n -o ConnectTimeout=10 -o StrictHostKeyChecking=no "cumulus@$SWIP" 'hostname; ip -br addr show lo; sudo vtysh -c "show bgp summary"' 2>&1 \
  | awk -v h="$SW" '{ printf "\033[1;92m%s\033[0m | %s\n", h, $0 }'
```

At this stage the loopback carries only `127.0.0.1/8`, no `10.253.x.x/32` address is
assigned, BGP is not running, and `nv config show -o commands` returns only the factory
defaults. Re-run with `SW` set to each switch to confirm they all start clean; Steps 5
and 8 change this.

## Step 4: Configure the switches

Set `fabricId` in `fabric-config.3tier.l3evpn.yaml` to `1`. This step assigns
hostnames, ASNs, loopbacks, the fabric point-to-point addresses (leaf-to-spine and
spine-to-super-spine), and the host downlinks. It may take a few minutes to complete:

```bash
metalcloud-cli fabric configure-switches 1 --config-source fabric-config.3tier.l3evpn.yaml
```

## Step 5: Deploy the underlay addressing

The first deploy pushes hostnames, loopbacks, point-to-point addresses, and port
settings. It is asynchronous; wait for its job group to finish before continuing:

```bash
wait_for_job_group "$(metalcloud-cli fabric deploy 1 -f json | jq -r '.jobGroupId')"
```

The deploy pushed the hostnames, loopbacks, and point-to-point addresses to every
switch. Re-run the check against each switch and compare with the Step 3 baseline:

```bash
# The awk lines resolve SW to its IP and password; these commands then run on the switch:
#     hostname                     (its configured hostname)
#     ip -br addr show lo          (loopback addresses)
#     nv config show -o commands   (the full switch configuration, as NVUE commands)
SW=leaf-pod00-su00-r0    # any hostname from the list in Step 3
SWIP=$(awk -v s="$SW" '$2=="identifierString:" && $3==s{f=1} f && $1=="managementAddress:"{print $2; exit}' ~/nvidia/switches.3tier.yaml)
SWPW=$(awk '/managementPassword:/{print $2; exit}' ~/nvidia/switches.3tier.yaml)
sshpass -p "$SWPW" ssh -n -o ConnectTimeout=10 -o StrictHostKeyChecking=no "cumulus@$SWIP" 'hostname; ip -br addr show lo; nv config show -o commands' 2>&1 \
  | awk -v h="$SW" '{ printf "\033[1;92m%s\033[0m | %s\n", h, $0 }'
```

The switch now reports its assigned hostname and a `10.253.128.x/32` loopback
(`leaf-pod00-su00-r0` is `10.253.128.1`, `r1` is `.2`, and so on, continuing into the
second POD; the spines and super-spines are addressed the same way), and `nv config show
-o commands` returns the full configuration where the baseline showed only defaults.

## Step 6: Discover links and redeploy

With the ports up, re-scan the fabric so the discovered links become managed, then
deploy again:

```bash
wait_for_job_group "$(metalcloud-cli fabric rescan-links 1 -f json | jq -r '.jobGroupId')"
```

```bash
wait_for_job_group "$(metalcloud-cli fabric deploy 1 -f json | jq -r '.jobGroupId')"
```

The rescan reads each switch's LLDP neighbours and records the discovered links in the
fabric database. Confirm a switch now sees its neighbours over LLDP:

```bash
# The awk lines resolve SW to its IP and password; this command then runs on the switch:
#     nv show interface lldp   (the LLDP neighbour discovered on each port)
SW=leaf-pod00-su00-r0    # any hostname from the list in Step 3
SWIP=$(awk -v s="$SW" '$2=="identifierString:" && $3==s{f=1} f && $1=="managementAddress:"{print $2; exit}' ~/nvidia/switches.3tier.yaml)
SWPW=$(awk '/managementPassword:/{print $2; exit}' ~/nvidia/switches.3tier.yaml)
sshpass -p "$SWPW" ssh -n -o ConnectTimeout=10 -o StrictHostKeyChecking=no "cumulus@$SWIP" 'nv show interface lldp' 2>&1 \
  | awk -v h="$SW" '{ printf "\033[1;92m%s\033[0m | %s\n", h, $0 }'
```

Each fabric-facing port lists the neighbour it discovered: a leaf sees its spines, a
spine sees the leaves below it and the super-spines above it, and a super-spine sees the
spines. These are the links the rescan imported and the redeploy confirmed.

## Step 7: Register the fabric templates

`fabric-config.3tier.l3evpn.yaml` names the Cumulus 5.14 templates under
`cumulus-5.14-templates/`. Register them in two commands. The order matters: the base
profile installs the QoS, adaptive-routing, and VTEP configuration that the BGP and
EVPN profiles depend on.

```bash
metalcloud-cli fabric configure-freeform 1 \
        --config-source fabric-config.3tier.l3evpn.yaml --verify-render
```

```bash
metalcloud-cli fabric configure-bgp 1 \
        --config-source fabric-config.3tier.l3evpn.yaml --verify-render
```

`--verify-render` renders every switch's configuration on the controller and stops
before writing if any switch fails to render.

## Step 8: Deploy the fabric

A single deploy applies the base, underlay, overlay, and QoS profiles in order. This
is the longest step, about 10 to 12 minutes:

```bash
wait_for_job_group "$(metalcloud-cli fabric deploy 1 -f json | jq -r '.jobGroupId')"
```

Continue only once every job reports success. BGP and EVPN come up during this deploy,
including the inter-POD EVPN routes relayed through the super-spine tier.

This deploy brings up BGP. Compare with the Step 3 baseline, where BGP was not running.
The block prints the underlay summary and the EVPN overlay summary together:

```bash
# The awk lines resolve SW to its IP and password; this runs on the switch, in one vtysh
# session with two show commands:
#     show bgp summary             (underlay BGP neighbour table)
#     show bgp l2vpn evpn summary  (EVPN overlay neighbour table)
SW=leaf-pod00-su00-r0    # any hostname from the list in Step 3
SWIP=$(awk -v s="$SW" '$2=="identifierString:" && $3==s{f=1} f && $1=="managementAddress:"{print $2; exit}' ~/nvidia/switches.3tier.yaml)
SWPW=$(awk '/managementPassword:/{print $2; exit}' ~/nvidia/switches.3tier.yaml)
sshpass -p "$SWPW" ssh -n -o ConnectTimeout=10 -o StrictHostKeyChecking=no "cumulus@$SWIP" 'sudo vtysh -c "show bgp summary" -c "show bgp l2vpn evpn summary"' 2>&1 \
  | awk -v h="$SW" '{ printf "\033[1;92m%s\033[0m | %s\n", h, $0 }'
```

Every switch now has established underlay sessions, each with a non-zero prefix count in
place of `Idle` or `Active`. The EVPN overlay runs between the leaves and the super-spine
relay `ssp-group00-s00` and `ssp-group00-s01`; the transit spines carry only the underlay,
so their EVPN summary is empty. Run the EVPN summary against a leaf or a super-spine to see
the overlay sessions.

## Step 9: Register the HGX endpoints

Register the eight HGX hosts as endpoints. Each host binds to eight leaf ports, one
per rail. The four hosts of the first POD sit on `leaf-pod00-su00-r*` and the four of
the second POD on `leaf-pod01-su00-r*`. The definitions are in `endpoints.3tier.yaml`:

```bash
metalcloud-cli endpoint create-bulk --config-source endpoints.3tier.yaml
```

List the endpoints to confirm all eight were created:

```bash
metalcloud-cli endpoint list --filter-site 1
```

Do not rename the endpoints. The Terraform manifest resolves them by label
(`hgx-pod00-su00-h*`, `hgx-pod01-su00-h*`).

## Step 10: Create the tenant route domain and profile

Create the tenant VRF (route domain) and the L3-only logical network profile that the
tenant network is built from:

```bash
metalcloud-cli route-domain create --config-source route-domain.3tier.yaml
```

```bash
metalcloud-cli logical-network-profile create vxlan --config-source l3-profile.3tier.yaml
```

The L3VNI is allocated automatically for the fabric. Keep the profile label
`tenant-l3`; the Terraform manifest resolves it by that label.

## Step 11: Onboard the tenant with Terraform

The Terraform manifest `terraform/nvidia-spectrumx-3tier.tf` creates the tenant
infrastructure, builds an L3 network from the `tenant-l3` profile, attaches the eight
endpoints with eight interfaces each, and deploys:

```bash
cd ~/nvidia/terraform/
terraform init
terraform apply
cd ~/nvidia
```

The deploy takes about 5 minutes. When it completes, the attached hosts' rail gateways
are live.

Terraform created the tenant VRF, attached the endpoints, and deployed. The tenant VRF
and the host rail gateways live on the leaves. Inspect a leaf:

```bash
# The awk lines resolve SW to its IP and password; these commands then run on the switch,
# all scoped to the tenant1 VRF:
#     ip -br link show type vrf                            (VRFs present, including tenant1)
#     ip -br addr show vrf tenant1 | grep -E "swp|172\."   (rail gateway /31s in the VRF)
#     sudo vtysh -c "show bgp vrf tenant1 ipv4 unicast"    (tenant routes learned by BGP)
#              -c "show ip route vrf tenant1"              (the tenant VRF routing table)
SW=leaf-pod00-su00-r0    # a leaf; see the leaf list in Step 3
SWIP=$(awk -v s="$SW" '$2=="identifierString:" && $3==s{f=1} f && $1=="managementAddress:"{print $2; exit}' ~/nvidia/switches.3tier.yaml)
SWPW=$(awk '/managementPassword:/{print $2; exit}' ~/nvidia/switches.3tier.yaml)
sshpass -p "$SWPW" ssh -n -o ConnectTimeout=10 -o StrictHostKeyChecking=no "cumulus@$SWIP" 'ip -br link show type vrf; ip -br addr show vrf tenant1 | grep -E "swp|172\."; sudo vtysh -c "show bgp vrf tenant1 ipv4 unicast" -c "show ip route vrf tenant1"' 2>&1 \
  | awk -v h="$SW" '{ printf "\033[1;92m%s\033[0m | %s\n", h, $0 }'
```

`tenant1` appears in the VRF list, the host-facing `swp` ports carry their `172.x` rail
gateway `/31`s inside it, and the VRF routing table holds both the local rail subnets and
the remote ones learned over EVPN, including the rails in the other POD reached across the
super-spine tier.

Neither the spines nor the super-spines hold the tenant VRF; that lives on the leaves. On
the super-spine overlay relay you can see the type-5 host routes it re-advertises:

```bash
# The awk lines resolve SW to its IP and password; this command runs on the relay switch:
#     sudo vtysh -c "show bgp l2vpn evpn route type prefix"
#         (the EVPN type-5 host routes this switch re-advertises)
SW=ssp-group00-s00    # the overlay relay: ssp-group00-s00, ssp-group00-s01
SWIP=$(awk -v s="$SW" '$2=="identifierString:" && $3==s{f=1} f && $1=="managementAddress:"{print $2; exit}' ~/nvidia/switches.3tier.yaml)
SWPW=$(awk '/managementPassword:/{print $2; exit}' ~/nvidia/switches.3tier.yaml)
sshpass -p "$SWPW" ssh -n -o ConnectTimeout=10 -o StrictHostKeyChecking=no "cumulus@$SWIP" 'sudo vtysh -c "show bgp l2vpn evpn route type prefix"' 2>&1 \
  | awk -v h="$SW" '{ printf "\033[1;92m%s\033[0m | %s\n", h, $0 }'
```

This is the control-plane state behind the host-to-host reachability that Step 13
verifies from the hosts.

## Step 12: Configure the HGX hosts

Each host has eight rail NICs (`eth_rail0` through `eth_rail7`) at MTU 9216. Each rail
takes a `/31`, with the host on the even address and the leaf gateway on the odd one.
For host node `h` on rail `r` in POD `p`, the host address is `172.(16 + 2*r).p.(2*h)`
and the gateway is one higher. The rail sets the second octet, the POD sets the third
(POD0 = 0, POD1 = 1), and the node sets the fourth (h00 = 0, h08 = 16, h16 = 32,
h24 = 48):

| rail | NIC | 2nd octet |
|---|---|---|
| 0 | `eth_rail0` | 172.16 |
| 1 | `eth_rail1` | 172.18 |
| 2 | `eth_rail2` | 172.20 |
| 3 | `eth_rail3` | 172.22 |
| 4 | `eth_rail4` | 172.24 |
| 5 | `eth_rail5` | 172.26 |
| 6 | `eth_rail6` | 172.28 |
| 7 | `eth_rail7` | 172.30 |

The complete per-host netplan files are staged on the jumpstation under `netplan/3tier/`,
one per host (`hgx-pod00-su00-h00.yaml` through `hgx-pod01-su00-h24.yaml`). Each holds
all eight rails and installs to `/etc/netplan/60-spectrum-x.yaml` on its host.

The hosts are reachable at `192.168.200.31` through `.38` as user `ubuntu` (POD0 hosts
`.31` to `.34`, POD1 hosts `.35` to `.38`).

First, capture each host's rail state *before* applying netplan, so there is a baseline to
compare against. The `eth_rail` NICs carry no `172.x` addresses yet and the routing table
holds no rail routes:

```bash
cd ~/nvidia
export SSHPASS=nvidia   # the HGX hosts are ubuntu:nvidia
for ip in 192.168.200.{31..38}; do
  host=$(sshpass -e ssh -n -o ConnectTimeout=10 -o StrictHostKeyChecking=no "ubuntu@$ip" hostname 2>/dev/null)
  sshpass -e ssh -n -o ConnectTimeout=10 -o StrictHostKeyChecking=no "ubuntu@$ip" 'ip -br address show; ip route show' 2>&1 \
    | awk -v h="${host:-$ip}" '{ printf "\033[1;92m%s\033[0m | %s\n", h, $0 }'
done
```

Now push each host the file named for it and apply it. This loop reads each host's name,
copies its file, installs it with mode 0600, and runs `netplan apply`:

```bash
cd ~/nvidia
export SSHPASS=nvidia   # the HGX hosts are ubuntu:nvidia
for ip in 192.168.200.{31..38}; do
  host=$(sshpass -e ssh -n -o ConnectTimeout=10 -o StrictHostKeyChecking=no "ubuntu@$ip" hostname 2>/dev/null)
  {
    sshpass -e scp -o StrictHostKeyChecking=no "netplan/3tier/$host.yaml" "ubuntu@$ip:/tmp/60-spectrum-x.yaml" &&
    sshpass -e ssh -n -o ConnectTimeout=10 -o StrictHostKeyChecking=no "ubuntu@$ip" \
      'sudo install -m 600 /tmp/60-spectrum-x.yaml /etc/netplan/60-spectrum-x.yaml && sudo netplan apply && rm -f /tmp/60-spectrum-x.yaml' &&
    echo "netplan applied"
  } 2>&1 | awk -v h="${host:-$ip}" '{ printf "\033[1;92m%s\033[0m | %s\n", h, $0 }'
done
```

Keying on `hostname` makes the loop correct no matter which management address Air gave
each host. The lab's `ubuntu` user has passwordless `sudo`; if yours does not, run the
two `sudo` commands by hand on each host after copying its file. Each host's output is
prefixed with its name in green. A clean apply prints `netplan applied`, and any scp or
`netplan` warnings appear under the same host label.

Re-run the same two commands to see the effect of the netplan change. Each `eth_rail` NIC
is now `UP` with its `/31` address, and the routing table has gained the per-rail `/15` and
`/12` rail routes (via each rail gateway) that carry the RoCE traffic, none of which were
present in the baseline above:

```bash
cd ~/nvidia
export SSHPASS=nvidia   # the HGX hosts are ubuntu:nvidia
for ip in 192.168.200.{31..38}; do
  host=$(sshpass -e ssh -n -o ConnectTimeout=10 -o StrictHostKeyChecking=no "ubuntu@$ip" hostname 2>/dev/null)
  sshpass -e ssh -n -o ConnectTimeout=10 -o StrictHostKeyChecking=no "ubuntu@$ip" 'ip -br address show; ip route show' 2>&1 \
    | awk -v h="${host:-$ip}" '{ printf "\033[1;92m%s\033[0m | %s\n", h, $0 }'
done
```

## Step 13: Verify connectivity

Before running the checks, confirm that the Terraform deployment from Step 11 has
finished. The following command refreshes every 10 seconds; leave it running until the
deploy status shows finished:

```bash
watch -n 10 "metalcloud-cli infrastructure list"
```

The output should look like this:

```
┌────┬─────────┬──────────────┬────────┬───────┬──────┬─────────────────────┬─────────────────────┬───────────────┬───────────┐
│ ID │ LABEL   │ CONFIG LABEL │ STATUS │ OWNER │ SITE │ CREATED             │ UPDATED             │ DEPLOY STATUS │ DEPLOY ID │
├────┼─────────┼──────────────┼────────┼───────┼──────┼─────────────────────┼─────────────────────┼───────────────┼───────────┤
│  1 │ tenant1 │ tenant1      │ active │     1 │    1 │ 16 Jul 26 15:26 UTC │ 16 Jul 26 15:30 UTC │ finished      │           │
└────┴─────────┴──────────────┴────────┴───────┴──────┴─────────────────────┴─────────────────────┴───────────────┴───────────┘
```

The rail `/31`s live only on the hosts, so the ping sweep has to run on each host, not
on the jumpstation. This block drives all eight hosts from the jumpstation: it SSHes in
with the lab credentials (`ubuntu` / `nvidia`, hardcoded so it never prompts) and runs
the full rail mesh on each one, covering all eight rails across both PODs and all four
hosts (64 targets per host, including the same-rail peers in the other POD). Every
target should answer, so a clean fabric reports `64 passed, 0 failed` on all eight hosts.
Each host's output is prefixed with its name in green, and the counts are coloured: the
pass count green, any failures red.

```bash
cd ~/nvidia
export SSHPASS=nvidia   # the HGX hosts are ubuntu:nvidia

# Runs on each host: ping every host on all eight rails in both PODs, retrying for up to
# ~30s so any rail still converging right after the deploy has time to come up. A target
# drops off the retry list as soon as it answers; only targets still down at the end fail.
mesh='targets=""
for r in 16 18 20 22 24 26 28 30; do          # eth_rail0 .. eth_rail7 (second octet)
  for p in 0 1; do                            # POD0, POD1 (third octet)
    for h in 0 16 32 48; do targets="$targets 172.$r.$p.$h"; done   # h00 h08 h16 h24
  done
done
pending="$targets"
for attempt in 1 2 3 4 5 6; do
  still=""
  for ip in $pending; do ping -c1 -W2 "$ip" >/dev/null 2>&1 || still="$still $ip"; done
  pending="$still"; [ -z "$pending" ] && break
  sleep 5
done
total=0; for ip in $targets; do total=$((total + 1)); done
fail=0;  for ip in $pending; do echo "FAIL $ip"; fail=$((fail + 1)); done
echo "host mesh: $((total - fail)) passed, $fail failed"'

for ip in 192.168.200.{31..38}; do
  host=$(sshpass -e ssh -n -o ConnectTimeout=10 -o StrictHostKeyChecking=no "ubuntu@$ip" hostname 2>/dev/null)
  sshpass -e ssh -n -o ConnectTimeout=10 -o StrictHostKeyChecking=no "ubuntu@$ip" "$mesh" 2>&1 \
    | awk -v h="${host:-$ip}" '
        { s=$0
          if (s ~ /^FAIL /) { s="\033[91m" s "\033[0m" }
          else {
            gsub(/[0-9]+ passed/,      "\033[92m&\033[0m", s)
            gsub(/[1-9][0-9]* failed/, "\033[91m&\033[0m", s)
          }
          printf "\033[1;92m%s\033[0m | %s\n", h, s
        }'
done
```

Reaching a same-rail host in the other POD (for example `172.16.0.0` to `172.16.1.0`)
is a leaf-to-leaf tunnel whose underlay crosses the super-spine tier. A clean fabric
prints eight green-labelled `host mesh: 64 passed, 0 failed` lines and nothing else. BGP
and EVPN can still be converging in the first seconds after the deploy, so the sweep
retries each target for up to about thirty seconds rather than reporting a false failure;
anything still unreachable after that is listed as a red `FAIL <ip>` line under the host
that could not reach it. Re-running the block is safe.

## Result

| Check | Expected |
|---|---|
| `fabric configure-switches` | devices patched=20, links created=512, /31 strategies added=576 |
| Endpoints | 8 created |
| Underlay BGP | all sessions established across all three tiers, 0 down |
| Tenant | `tenant1` L3 network deployed, one L3VNI |
| Host mesh | `64 passed, 0 failed` from all eight hosts, both PODs (64 targets each, 512 total) |

## Troubleshooting

- **The CLI cannot reach the controller.** If a `metalcloud-cli` command fails with a
  connection or TLS error, or `site agents 1` returns no agent, the controller may still
  be starting, or the Site Controller may have lost its link to the Global Controller
  after a restart. Log in to the Global Controller as `root` (`ssh -l root 192.168.200.3`,
  password `MetalsoftR0cks@$@$`) and run `kw` to watch the Kubernetes pods until each
  reaches `Running`; if any stay stuck, run `k-restart-all -A` to force a restart. On the
  Site Controller (`ssh -l root 192.168.200.2`, same password), run `docker ps` to confirm
  the `nfs-server` and `ms-agent` containers are `Up`, `docker logs -f ms-agent` to read
  the agent log, and `dcrestart` to restart the containers if `ms-agent` is not registering
  with the Global Controller.
- **A deploy job fails.** Read the job with `metalcloud-cli job get <id>`, correct the
  cause, and re-run the deploy step. BGP does not come up until the Step 8 deploy
  succeeds on every switch.
- **`get-ports` is empty in Step 3.** The switch is unreachable. Verify the management
  address and password in `switches.3tier.yaml`, then re-run discovery.
- **BFD sessions do not establish.** NVIDIA Air's Cumulus VX has no BFD daemon, so BFD
  liveness cannot be observed on the simulator. The configuration is applied correctly
  and matches the reference; BFD is a hardware-only check.
