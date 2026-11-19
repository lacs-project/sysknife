# The host the audit-tamper demo runs on: a bare Ubuntu 26.04 with the few tools
# the recording shows (sqlite3) and the one the seeding agent needs (python3).
# Built by audit-tamper.sh; the sysknife binaries are mounted in, not baked in,
# so the image never goes stale against the checkout.
FROM docker.io/library/ubuntu:26.04
RUN apt-get update -y \
 && apt-get install -y --no-install-recommends ca-certificates sqlite3 procps iproute2 python3-minimal \
 && rm -rf /var/lib/apt/lists/*
