# Guard: containers and infrastructure as code

Dockerfiles, `docker-compose.yml` and Terraform describe the machine your code runs on. A mistake
here is not a bug in one endpoint — it is a door in the wall around all of them.

<a id="run-as-non-root"></a>
## Run the container as a non-root user

Without a `USER` line, everything in the image runs as root. Any code-execution bug in your app is
then root inside the container, which is the first half of a container escape.

```diff
  FROM node:22-alpine
  WORKDIR /app
  COPY --chown=node:node . .
  RUN npm ci --omit=dev
+ USER node
  CMD ["node", "server.js"]
```

Most official images ship a suitable unprivileged user already (`node`, `nginx`, `postgres`). If
yours does not, make one:

```dockerfile
RUN addgroup -S app && adduser -S app -G app
USER app
```

Where: the Dockerfile, after the last step that needs to write to system paths. If the app breaks
on a permission error, fix the file ownership with `COPY --chown=`, not by deleting the `USER`.

Protects against: a remote-code-execution bug becoming root, and a compromised build-time
dependency writing outside the app directory.
Does **not** protect against: anything the app user can already reach — your database credentials
still live in the same process.

<a id="no-baked-secrets"></a>
## Never bake a secret into an image or a compose file

`ENV` and `ARG` values are stored in the image layers. Anyone who can pull the image reads them
with `docker history`, and deleting the line in a later layer does not remove it.

```diff
- ENV STRIPE_SECRET_KEY=sk_live_51H8xQ2eZvKYlo2C
- ARG DATABASE_URL=postgres://user:hunter2@db.example.com/prod
+ # inject at RUN TIME instead — nothing secret is stored in the image
+ # docker run -e STRIPE_SECRET_KEY="$STRIPE_SECRET_KEY" myapp
```

```diff
  # docker-compose.yml
  services:
    api:
-     environment:
-       - DATABASE_URL=postgres://user:hunter2@db/prod
+     env_file: .env          # and keep .env out of git
```

For build-time credentials (a private npm registry token), use a build secret, which is mounted for
one command and never enters a layer:

```dockerfile
RUN --mount=type=secret,id=npmrc,target=/root/.npmrc npm ci
# docker build --secret id=npmrc,src=$HOME/.npmrc .
```

Where: the Dockerfile and every compose file. Anything already committed must be rotated — the
value is in your git history and in every image you pushed.

Protects against: a credential leaking to anyone who pulls the image or reads the repo.
Does **not** protect against: a secret already published. Rotate first, then fix the file.

<a id="pin-base-images"></a>
## Pin base images to a digest

`FROM node:latest` means your build is not reproducible and a compromised upstream tag lands in
your next deploy with no change on your side.

```diff
- FROM node:latest
+ FROM node:22.11.0-alpine@sha256:f2dc6eea95f787e25f173ba9904c9d0647ab2506178c7b5b7c5a3d02bc4af145
```

Get the digest with `docker buildx imagetools inspect node:22-alpine`. Renovate or Dependabot can
keep the pin current, which is what makes pinning sustainable rather than a thing you do once.

Protects against: a moved tag silently changing what you ship.
Does **not** protect against: a vulnerability that was already in the digest you pinned. Pinning
without an update process is just a slower kind of stale.

<a id="compose-exposure"></a>
## Do not publish databases or hand over the Docker socket

```diff
  services:
    db:
      image: postgres:16
      ports:
-       - "5432:5432"          # binds 0.0.0.0 — the internet, on a host with no firewall
+       - "127.0.0.1:5432:5432"  # local only; other services reach it by name on the compose network
```

Services in the same compose file already reach each other by name (`postgres://db:5432`). A
published port is only for reaching the database *from outside*, which is almost never what you
want in production.

```diff
    worker:
-     privileged: true                       # disables nearly every container boundary
-     volumes:
-       - /var/run/docker.sock:/var/run/docker.sock   # = root on the host
+     cap_add: ["SYS_TIME"]                  # grant the one capability you actually need
```

Mounting the Docker socket gives the container full control of the daemon, and the daemon runs as
root on the host. Treat it as identical to handing out host root.

Protects against: an unauthenticated database on the public internet — the single most common way
a side project ends up in a ransom note — and a container escape by design.
Does **not** protect against: a weak database password. Bind locally *and* set a real one.

<a id="terraform-network"></a>
## Do not open a security group to the world

```diff
  resource "aws_security_group_rule" "db" {
    type        = "ingress"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
-   cidr_blocks = ["0.0.0.0/0"]
+   security_groups = [aws_security_group.app.id]   # only the app tier, by identity
  }
```

`0.0.0.0/0` on 80 and 443 is what a public web server is for. On anything else — 22, 3389, or a
database port — it is an open door with a password on it.

```diff
  resource "aws_s3_bucket_acl" "assets" {
-   acl = "public-read"
+   acl = "private"
  }
+ resource "aws_s3_bucket_public_access_block" "assets" {
+   bucket                  = aws_s3_bucket.assets.id
+   block_public_acls       = true
+   block_public_policy     = true
+   ignore_public_acls      = true
+   restrict_public_buckets = true
+ }
```

Serve public assets through a CDN with an origin access identity instead of a public bucket.

Protects against: anyone on the internet reaching your database, your admin port, or your object
storage directly.
Does **not** protect against: an attacker who is already inside the VPC. Network rules are one
layer; authentication is still required behind them.

<a id="terraform-state"></a>
## Keep state files out of git

`terraform.tfstate` records every attribute of every resource in plaintext — generated passwords,
private keys, connection strings. No secret scanner is shaped to catch them, because the values
have no recognisable prefix.

```diff
  # .gitignore
+ *.tfstate
+ *.tfstate.*
+ .terraform/
+ *.tfvars          # except example files
+ !example.tfvars
```

Move state to a remote backend with encryption and locking:

```hcl
terraform {
  backend "s3" {
    bucket         = "my-tfstate"
    key            = "prod/terraform.tfstate"
    region         = "eu-central-1"
    encrypt        = true
    dynamodb_table = "tf-locks"
  }
}
```

Where: `.gitignore` and the root module. If a state file is already committed, treat every
credential it contains as burned and rotate them — then purge it from history.

Protects against: publishing your entire infrastructure's secrets in a file nobody thinks to check.
Does **not** protect against: the copy already in your git history. Rotation is the only fix for
that.
