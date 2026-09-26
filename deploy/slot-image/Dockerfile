# Blessed slot image: everything a slot gets out of the box.
# Admin rebuilds this ONE image for all slots (P3+); slot containers are
# created from it, user data lives on per-slot volumes (never in the image).
# Build on server: docker build -t dach-slot:latest deploy/slot-image/
FROM ubuntu:26.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash ca-certificates curl \
    python3 python3-pip python3-venv \
    postgresql postgresql-contrib \
    podman fuse-overlayfs slirp4netns uidmap \
    docker.io \
 && rm -rf /var/lib/apt/lists/*

# rootless podman inside the container (slot's own containers, own disk)
RUN echo 'root:100000:65536' > /etc/subuid \
 && echo 'root:100000:65536' > /etc/subgid

# force fuse-overlayfs: native overlay mount is denied inside an
# unprivileged outer container ("remount /: permission denied")
RUN mkdir -p /etc/containers && printf '[storage]\ndriver = "overlay"\n[storage.options.overlay]\nmount_program = "/usr/bin/fuse-overlayfs"\n' > /etc/containers/storage.conf

# shared read-only assets mountpoint (host dir mounted :ro at run)
RUN mkdir -p /opt/shared

CMD ["sleep", "infinity"]
