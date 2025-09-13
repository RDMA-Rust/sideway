# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.2](https://github.com/RDMA-Rust/sideway/compare/v0.3.1...v0.3.2) - 2025-09-13

### Added

- *(rdmacm)* define error types for all RDMA CM methods
- *(rdmacm)* implement AsRawFd for EventChannel

### Other

- remove codecov upload token
- *(ibverbs)* add more tests for Device and DeviceList
- *(rdmacm)* add test for using event channel fd in a seperated thread

## [0.3.1](https://github.com/RDMA-Rust/sideway/compare/v0.3.0...v0.3.1) - 2025-08-16

### Added

- *(ibverbs)* add QueuePair::query for querying QP attributes
- *(qp)* support send_imm / write_imm and read opcode

### Other

- *(ibverbs)* add elided lifetime marks to make cargo clippy quiet
- add documentations on PD and MR
- add documentation for completion module
- add documentation for device module
- add documentation for device context module
- add documentation for address module
- add documentation for queue pair and access flags
- use variables directly in the `format!` string

## [0.3.0](https://github.com/RDMA-Rust/sideway/compare/v0.2.1...v0.3.0) - 2025-06-15

### Added

- use unwrap_uncheck in data path functions
- *(ibverbs)* derive more attributes for GidType
- *(address)* derive Serdes for GidType
- *(ibverbs)* only provide unsafe interface for registering MR
- remove debug configuration type
- *(ibverbs)* improve Device and DeviceList implementation

### Other

- *(qp)* define CreateQueuePairError for create_qp
- *(qp)* change ModifyQueuePairError to struct to align the error handling logic
- *(qp)* define PostRecvError for post_recv
- *(ibverbs)* define error type for poll cq
- *(ibverbs)* define more error types for completion
- *(ibverbs)* return String instead of Option<String> for device name
- rename Infiniband to InfiniBand which is more formal
- *(cargo)* bump thiserror to v2.0 and postcard to v1.1
- replace lazy_static with std::sync::LazyLock
- define more error types for DeviceContext

## [0.2.1](https://github.com/RDMA-Rust/sideway/compare/v0.2.0...v0.2.1) - 2025-02-09

### Added

- add more APIs for reading device attribute

### Other

- *(device_context)* use ibv_query_gid_ex/table without the prefix underscore
- *(devinfo)* refactor ibv_devinfo to mimic the original rdma-core implementation
- *(rdmacm)* correct module names and paths in comments
- *(device)* split guid as a unique type and use String for fw_ver


## v0.1.0 (2024-09-01)

### Documentation

 - <csr-id-a807a1b2fe471dea6a4392e3b003219c2917df97/> provide description and license for release
 - <csr-id-48c20c61646ce1efa16b8c999fc75547def981e0/> add FujiZ as one of the authors

### New Features

 - <csr-id-2b20ee92ba2923876e54ac432abcff33f596aa6c/> provide query_gid_table for convenient GID operations
   To keep compatibility, we would scan sysfs to get gid table when there
   is no ibv_query_gid_table symbol in libibverbs, just as what they do in
   the libibverbs original C implementation.
 - <csr-id-cc4be2c1c9b8c2483349cf0b0611c82eccd18bda/> implement trait for CQ
   A trait called CompletionQueue is introduced to interact with other
   modules in this crate; The original wrapper struct for ibv_cq and
   ibv_cq_ex are renamed to BasicCompletionQueue and
   ExtendedCompletionQueue, respectively.
 - <csr-id-70a97156498e97a5339a598f4652d21be8d78490/> add setup method for each fields in grh
 - <csr-id-b99cabe6713a5e440ff48053e16bb0cdcb66a49f/> add more attr for INIT -> RTR transition
   Note that the example will fail with current setup.
 - <csr-id-138dc1529933bda00d22e00c8e67c78c7c8a7f6b/> implement modify on QueuePair
   Construct QueuePairAttribute using builder pattern and modify the QP
   through QueuePair::modify().
 - <csr-id-8ac2f358883b7a6631fe0c2ccfd0415cb0d64285/> add support for qp and qp_ex
 - <csr-id-873dabd6fcce1b802455ae6917fc3ed80f0eccf6/> add create_comp_channel and create_cq_builder
 - <csr-id-bbcd507dd0a1bc9fbf9adf7b5270e6c070d95dbf/> add support for cq and comp_channel
   1. implement generic builder for both cq and cq_ex
   2. implement comp_channel and associate its lifetime with cq
 - <csr-id-d32bc833c51c85b37e11459062003dbc522d8d7c/> an initial implementation of safe wrapper on rdmacm
 - <csr-id-70915408e88f5ae5c10340e66d1a8e3ccd4f2bc3/> an initial implementation of safe wrapper on ibverbs

### Bug Fixes

 - <csr-id-5112dd1132d596a913c48678e7a395ce2b6cc1f4/> fix modifying QP to RTR and add modify to RTS

### Other

 - <csr-id-31ba5f57564156f87656533aeffd4e7fce38202e/> change rdma-mummy-sys to depend on release version
   Create a placeholder for changelog at the same time.

### Refactor

 - <csr-id-a0d51bb1f809aae44c0eb4ca34d18c4955bca371/> use enum Mtu instead of u32 as parameter
 - <csr-id-19b37736271623e2e7de76b5b2fb6f2c21d2a299/> move comp_channel and cq to completion module

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 23 commits contributed to the release.
 - 16 commits were understood as [conventional](https://www.conventionalcommits.org).
 - 0 issues like '(#ID)' were seen in commit messages

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **Uncategorized**
    - Provide description and license for release ([`a807a1b`](https://github.com/RDMA-Rust/sideway/commit/a807a1b2fe471dea6a4392e3b003219c2917df97))
    - Change rdma-mummy-sys to depend on release version ([`31ba5f5`](https://github.com/RDMA-Rust/sideway/commit/31ba5f57564156f87656533aeffd4e7fce38202e))
    - Merge pull request #19 from RDMA-Rust/fz/author ([`5cece9a`](https://github.com/RDMA-Rust/sideway/commit/5cece9a9732f95336454cb3848031d0049636f57))
    - Add FujiZ as one of the authors ([`48c20c6`](https://github.com/RDMA-Rust/sideway/commit/48c20c61646ce1efa16b8c999fc75547def981e0))
    - Merge pull request #16 from RDMA-Rust/dev/query_gid_table ([`75d76a1`](https://github.com/RDMA-Rust/sideway/commit/75d76a1b23a68ac2cb5ad4236ba26f44b7751900))
    - Fix modifying QP to RTR and add modify to RTS ([`5112dd1`](https://github.com/RDMA-Rust/sideway/commit/5112dd1132d596a913c48678e7a395ce2b6cc1f4))
    - Provide query_gid_table for convenient GID operations ([`2b20ee9`](https://github.com/RDMA-Rust/sideway/commit/2b20ee92ba2923876e54ac432abcff33f596aa6c))
    - Merge pull request #15 from RDMA-Rust/dev/cq-trait ([`1dd6999`](https://github.com/RDMA-Rust/sideway/commit/1dd6999cfc350f88f639697c049b6395b2a4dbad))
    - Implement trait for CQ ([`cc4be2c`](https://github.com/RDMA-Rust/sideway/commit/cc4be2c1c9b8c2483349cf0b0611c82eccd18bda))
    - Merge pull request #12 from RDMA-Rust/dev/modify-qp ([`e2fe5cd`](https://github.com/RDMA-Rust/sideway/commit/e2fe5cde87d6e70e138a965a3337f7ced9f02160))
    - Add setup method for each fields in grh ([`70a9715`](https://github.com/RDMA-Rust/sideway/commit/70a97156498e97a5339a598f4652d21be8d78490))
    - Use enum Mtu instead of u32 as parameter ([`a0d51bb`](https://github.com/RDMA-Rust/sideway/commit/a0d51bb1f809aae44c0eb4ca34d18c4955bca371))
    - Add more attr for INIT -> RTR transition ([`b99cabe`](https://github.com/RDMA-Rust/sideway/commit/b99cabe6713a5e440ff48053e16bb0cdcb66a49f))
    - Implement modify on QueuePair ([`138dc15`](https://github.com/RDMA-Rust/sideway/commit/138dc1529933bda00d22e00c8e67c78c7c8a7f6b))
    - Merge pull request #11 from RDMA-Rust/dev/qp ([`ca4e2f3`](https://github.com/RDMA-Rust/sideway/commit/ca4e2f33e1cb457fd96788444462f00c10de1bd4))
    - Add support for qp and qp_ex ([`8ac2f35`](https://github.com/RDMA-Rust/sideway/commit/8ac2f358883b7a6631fe0c2ccfd0415cb0d64285))
    - Merge pull request #10 from RDMA-Rust/dev/comp ([`e3da584`](https://github.com/RDMA-Rust/sideway/commit/e3da584ec0816a9eb54adaf5a49e5aa2ad5382ea))
    - Add create_comp_channel and create_cq_builder ([`873dabd`](https://github.com/RDMA-Rust/sideway/commit/873dabd6fcce1b802455ae6917fc3ed80f0eccf6))
    - Move comp_channel and cq to completion module ([`19b3773`](https://github.com/RDMA-Rust/sideway/commit/19b37736271623e2e7de76b5b2fb6f2c21d2a299))
    - Add support for cq and comp_channel ([`bbcd507`](https://github.com/RDMA-Rust/sideway/commit/bbcd507dd0a1bc9fbf9adf7b5270e6c070d95dbf))
    - An initial implementation of safe wrapper on rdmacm ([`d32bc83`](https://github.com/RDMA-Rust/sideway/commit/d32bc833c51c85b37e11459062003dbc522d8d7c))
    - An initial implementation of safe wrapper on ibverbs ([`7091540`](https://github.com/RDMA-Rust/sideway/commit/70915408e88f5ae5c10340e66d1a8e3ccd4f2bc3))
    - Initial commit ([`d33fde1`](https://github.com/RDMA-Rust/sideway/commit/d33fde144baa8a65ba2de1b8932c85a5f68c8274))
</details>

