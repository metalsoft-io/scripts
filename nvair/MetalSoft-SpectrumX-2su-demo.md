# MetalSoft for NVIDIA Spectrum-X: 2-SU Demo (512 GPU)


MetalSoft is an intelligent orchestration platform that transforms fragmented on-premises hardware into high-performance, fast-changing, secure, workload compliant infrastructure. It integrates both servers, switches, storage and more to provide a turnkey NCP solution. 

Build an NVIDIA SpectrumX 2 Scalability Unit fabric (512 GPUS) from scratch and deploy a tenancy using the MetalSoft CLI and Terraform. The fabric uses a two-tier leaf-spine design running EVPN over eBGP on Cumulus Linux 5.14.0. 


### The lab environment

The simulation packs everything needed to test the setup: The MetalSoft Global Controller and Site Controller, associated switches, links and HGX nodes.

To get started, deploy this simulation and then follow:

[Spectrum-X 2 SU demo Instructions](https://docs.metalsoft.io/fabric_manager/nvidia_air/spectrumx_2su_demo/)