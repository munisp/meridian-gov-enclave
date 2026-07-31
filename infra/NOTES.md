# gov-enclave infra notes

- `cilium/enclave-cnp.yaml` — enclave network lockdown per SPEC C:
  ingress only from the meridian-core `enclave-gateway`, DNS restricted to
  `*.enclave.svc.cluster.local`, egress only to `minio-enclave` (data ns,
  9000), `egressDeny: 0.0.0.0/0` (no internet, ever). Mirrors the mTLS
  service map: SPIFFE/mTLS authenticates, CNP restricts reachability.
- `cilium/tetragon-policies.yaml` — runtime security per SPEC C section 5:
  `enclave-worm-guard` logs every open of `/var/lib/enclave/worm/` and kills
  writers (Sigkill enforcement after the 2-week monitor window);
  `enclave-exec-trace` posts an audit event on any exec outside the allowlist
  (`enclave-gateway`, `ollama`).
- Cilium install values, policies for the other namespaces, the
  Hubble→`audit.events.v1` vector DaemonSet, and the 5-phase rollout plan
  live in meridian-core-platform `infra/cilium/`.
- docker-compose dev: none of this applies — compose networks provide dev
  isolation (SPEC C section 1).
