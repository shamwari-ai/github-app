#!/usr/bin/env bash
# Builds the Worker: what wrangler.toml's [build] command runs under
# `wrangler dev`, `wrangler deploy --dry-run` and Cloudflare Workers Builds.
#
# It is self-sufficient on purpose. The Workers Builds image (Ubuntu 24.04,
# Node, Python, Go, Ruby, build-essential, curl) has no Rust toolchain, so this
# installs rustup if it is missing, then the toolchain rust-toolchain.toml pins
# (stable, with the wasm32-unknown-unknown target), then the pinned
# worker-build, then builds. On a machine that already has Rust it only checks.
set -euo pipefail

# Keep in step with the `worker` crate in Cargo.toml.
WORKER_BUILD_VERSION="0.9.0"

cd "$(dirname "$0")/.."

export PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$PATH"

if ! command -v rustup >/dev/null 2>&1; then
  echo "build-worker: installing rustup (no toolchain on this machine)"
  curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs |
    sh -s -- -y --profile minimal --default-toolchain none --no-modify-path
fi

# Installs the channel, components and targets from rust-toolchain.toml.
rustup toolchain install
rustc --version
rustup target list --installed

cargo install -q worker-build --version "=${WORKER_BUILD_VERSION}" --locked
worker-build --release
