# Role: k8s-cp

Kubernetes control plane. Static pods under /etc/kubernetes/manifests/
(kube-apiserver, kube-scheduler, etcd), TLS certs under
/etc/kubernetes/pki/ with rotation drift, audit policy + log
writer. Tags: role=k8s-cp env=... cluster=<name> tier=cp.
