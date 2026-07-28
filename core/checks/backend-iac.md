# Backend / Infrastructure-as-Code checks

Applies to Dockerfiles, docker-compose, Kubernetes manifests, Terraform/Pulumi/CloudFormation,
and cloud config. Prefer `checkov`/`tfsec`/`trivy` when installed; fallback is reading the files.

## Docker
- **Runs as root** (no `USER` directive, or `USER root`). **P2**. Guard: add a non-root user.
- **Secrets baked into the image** — `ENV SECRET=...`, `ARG` secrets, or a copied `.env`. They
  persist in image layers. **P1/P0**. Guard: `secrets-management.md` (use runtime secrets).
- **`:latest` / unpinned base images** → unreproducible, silently vulnerable. **P3**.
- **Unnecessary packages / large attack surface**, `curl | sh` in build. **P2/P3**.
- **Exposed docker socket** (`/var/run/docker.sock` mounted). **P1**.

## docker-compose / K8s
- **Default or hardcoded credentials** (`POSTGRES_PASSWORD: postgres`, admin/admin). **P1**.
- **Ports bound to `0.0.0.0`** exposing internal services (DB, Redis, admin UIs) publicly.
  **P1/P2**.
- **`privileged: true`** containers / `hostNetwork` / `hostPath` mounts. **P1**.
- **No resource limits** (DoS). **P3**.
- **K8s secrets in plain manifests** committed to the repo. **P1**.

## Terraform / cloud
- **Public storage** — S3 bucket/GCS with public ACL or policy; no encryption. **P1/P0**.
- **Open security groups / firewall** — `0.0.0.0/0` on 22/3389/DB ports. **P1**.
- **IAM wildcards** — `Action: "*"`, `Resource: "*"`, overly broad roles. **P1/P2**.
- **Unencrypted resources** (RDS/EBS/queues without encryption at rest). **P2**.
- **Public database instances** / no VPC isolation. **P1**.
- **Logging/audit disabled** (CloudTrail off, no flow logs). **P3**.

## Secrets management (cross-cutting)
- **Secrets in state files** (`terraform.tfstate` committed — plaintext secrets). **P0/P1**.
- **No secret manager** (Vault/SM/Secrets Manager) — creds spread across env/files. **P2**.
- **CI runners with long-lived cloud keys** instead of OIDC. **P2**. See `supply-chain-cicd.md`.

## Verify
IaC misconfig is `confirmed` from the file. "Bucket is public" from Terraform is `confirmed` for
intent, but the live resource may differ — note that applied state is the ground truth.
