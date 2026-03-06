FROM golang:1.25

# Add the Debian debug symbols repository so that -dbgsym packages are
# available for real-world binary tests.
RUN echo 'deb http://deb.debian.org/debian-debug/ trixie-debug main' \
      > /etc/apt/sources.list.d/debug.list

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    binutils \
    gcc-aarch64-linux-gnu \
    binutils-aarch64-linux-gnu \
    libc6-dev-arm64-cross \
    grep \
    grep-dbgsym \
  && rm -rf /var/lib/apt/lists/*
