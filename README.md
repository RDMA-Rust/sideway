# Sideway

[![Crates.io](https://img.shields.io/crates/v/sideway.svg)](https://crates.io/crates/sideway)
[![Documentation](https://docs.rs/sideway/badge.svg)](https://docs.rs/sideway)
[![codecov](https://codecov.io/github/RDMA-Rust/sideway/graph/badge.svg?token=CNR6AJQ4KB)](https://codecov.io/gh/RDMA-Rust/sideway)
[![github-actions](https://github.com/RDMA-Rust/sideway/actions/workflows/test.yml/badge.svg)](https://github.com/RDMA-Rust/sideway/actions)

## Core concepts

Sideway is a wrapper for using RDMA programming APIs (which is written in C) in Rust flavor, built on [rdma-mummy-sys](https://github.com/RDMA-Rust/rdma-mummy-sys). We mainly
focus on bringing the new `ibverbs` APIs (`ibv_wr_*`, `ibv_start_poll`, etc.) into Rust world, the traditional `ibv_post_send`, `ibv_poll_cq` APIs would be wrapped, but
no performance guarantee will be provided. Besides, `libibmad`, `libibumad`, with a lot of other `rdma-core` parts are beyond our scope.

## Building and installing

### Install the Dependencies

#### The rdma-core libraries

Though we don't need rdma-core libraries for compiling (using `rdma-core-mummy`), we still require `rdma-core` installed when running, if not
installed, every non-inline C function would return `EOPNOTSUPP`.

- Debian / Ubuntu

```shell
apt install libibverbs1 librdmacm1 ibverbs-providers
```

- Fedora / CentOS / Rocky Linux

```shell
dnf install librdmacm libibverbs
```

If your RDMA NIC manufacture provides its own userspace / kernel module packages, for example, [NVIDIA MLNX_OFED](https://network.nvidia.com/products/infiniband-drivers/linux), you'd
better install them for better user experience and tech support.

#### Project DevOps tools

- Install `just` to use commands from `Justfile`, like `just test-all`

```shell
cargo install just
```

Or checkout https://github.com/casey/just?tab=readme-ov-file#packages for your specific platform installation guide.

- Install `cargo-nextest` for faster testing

```shell
cargo install cargo-nextest --locked
```

Or checkout https://nexte.st/docs/installation/pre-built-binaries/ for your specific platform installation guide.

- Install `cargo-llvm-cov` for coverage info

```shell
cargo +stable install cargo-llvm-cov --locked
```

### Build the library

```shell
cargo build --release
```

### Build all examples

```shell
cargo build --examples
```

## Getting started

Try some examples to examine your RDMA NIC status and how to use our APIs, for example, `show_gids` would print all GIDs on your machines, just like the script version
of `show_gids`.

```shell
cargo run --example show_gids

  Dev   | Port | Index |                   GID                   |    IPv4     |  Ver   | Netdev
--------+------+-------+-----------------------------------------+-------------+--------+--------
 rxe_0  |  1   |   0   | fe80:0000:0000:0000:5054:00ff:fe36:7656 |             | RoCEv2 | enp4s0
 rxe_0  |  1   |   1   | 0000:0000:0000:0000:0000:ffff:ac11:081c | 172.17.8.28 | RoCEv2 | enp4s0
 rxe_0  |  1   |   2   | 0000:0000:0000:0000:0000:ffff:ac11:081d | 172.17.8.29 | RoCEv2 | enp4s0
```

### Resources

- [RDMAmojo blogs](https://www.rdmamojo.com/)
- [RDMA manual pages](https://github.com/linux-rdma/rdma-core/tree/master/libibverbs/man)
- [Libibverbs examples](https://github.com/linux-rdma/rdma-core/tree/master/libibverbs/examples)
- [Librdmacm examples](https://github.com/linux-rdma/rdma-core/tree/master/librdmacm/examples)
