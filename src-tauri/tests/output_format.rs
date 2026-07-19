// Byte-exact export tests live beside the private formatter in src/output.rs.
// This integration-test target ensures Cargo discovers the project's test suite.
#[test]
fn integration_test_target_is_available() {
    assert_eq!("\r\n".as_bytes(), &[0x0d, 0x0a]);
}
