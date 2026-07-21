# MetalSoft for NVIDIA Spectrum-X: 3-Tier Demo (512 GPU)

MetalSoft is an intelligent orchestration platform that transforms fragmented on-premises hardware into high-performance, fast-changing, secure, workload compliant infrastructure. It integrates both servers, switches, storage and more to provide a turnkey NCP solution. 

<img src="https://docs.metalsoft.io/_astro/metalsoft-logo-default-registered.DxFqJBnC.svg" alt="drawing" width="200"  style="padding: 20px;"/>


Build an NVIDIA SpectrumX 3 tier fabric (512 GPUs) from scratch and deploy a tenancy using the MetalSoft CLI and Terraform. The fabric uses a two-tier leaf-spine design running EVPN over eBGP on Cumulus Linux 5.14.0. 


### The lab environment

The simulation packs everything needed to test the setup: The MetalSoft Global Controller and Site Controller, associated switches, links and HGX nodes.

<img src="https://docs.metalsoft.io/assets/nvidia-air-marketplace-documentation/fabric_view_links_discovered.png"  alt="drawing" width="400"  style="padding: 20px;"/>

### Getting started
To get started, deploy this simulation and then follow:

[Spectrum-X 3 tier demo Instructions](https://docs.metalsoft.io/fabric_manager/nvidia_air/spectrumx_3tier_demo/)