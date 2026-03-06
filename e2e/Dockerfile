FROM golang:1.25

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    binutils \
    gcc-aarch64-linux-gnu \
    binutils-aarch64-linux-gnu \
  && rm -rf /var/lib/apt/lists/*
