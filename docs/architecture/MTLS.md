# mTLS between API and workers

## Recommended (Kubernetes)
1. NetworkPolicy deny-by-default (`deploy/k8s/networkpolicy.yaml`)
2. Service mesh (Istio/Linkerd/Cilium) STRICT mTLS in namespace `aegis`
3. Redis/Postgres provider TLS (`rediss://`, SSL)

## Checklist
- [ ] Mesh PeerAuthentication STRICT
- [ ] Redis TLS + AUTH
- [ ] Postgres SSL
- [ ] NetworkPolicy applied
- [ ] No hostNetwork on API/worker pods
