# Role: k8s-node

Kubernetes worker. kubelet + container runtime + CNI plugins.
modules-load drop-ins for workload-specific kernel modules
(overlay, br_netfilter, sometimes vxlan / tcp_bbr). Tags:
role=k8s-node env=... cluster=<name> tier=worker.
