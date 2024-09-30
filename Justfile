test_command := if `echo $(command -v cargo-nextest 2>&1)` != "" { "cargo nextest run" } else { "cargo test" }

test:
    {{test_command}}

test-all:
    cargo clippy --all-targets -- -D warnings
    {{test_command}}

test-all-with-cov:
    cargo clippy --all-targets -- -D warnings
    cargo llvm-cov test --all-targets --locked --all-features --workspace --no-report
    cargo llvm-cov --no-report run --example show_gids
    cargo llvm-cov --no-report run --example ibv_devinfo
    cargo llvm-cov report --lcov --output-path lcov.info
