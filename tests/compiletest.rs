#[test]
fn compile_test() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/post_send_guard/*.rs");
}
