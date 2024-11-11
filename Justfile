test_command := if `echo $(command -v cargo-nextest 2>&1)` != "" { "cargo nextest run" } else { "cargo test" }
ip := `ip -4 addr show | awk '/inet / && !/127\.0\.0\.1/ {gsub("/[0-9][0-9]","",$2); print $2}' | head -n1`
rdma_dev := `ls /sys/class/infiniband/ 2>/dev/null | head -n1`

test:
    {{test_command}}

test-all:
    cargo clippy --all-targets -- -D warnings
    {{test_command}}

test-basic-with-cov:
    cargo clippy --all-targets -- -D warnings
    cargo llvm-cov test --all-targets --locked --all-features --workspace --no-report
    cargo llvm-cov --no-report run --example show_gids
    cargo llvm-cov --no-report run --example ibv_devinfo

test-rc-pingpong-with-cov:
    cargo llvm-cov --no-report run --features="debug" --example rc_pingpong_split -- -d {{rdma_dev}} -g 1 &
    sleep 2
    cargo llvm-cov --no-report run --features="debug" --example rc_pingpong_split -- -d {{rdma_dev}} -g 1 127.0.0.1

generate-cov:
    cargo llvm-cov report --lcov --output-path lcov.info
