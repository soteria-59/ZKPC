#[cfg(feature = "tpm")]
mod tpm_tests {
    use zkpc_agent::platform::tpm::TpmAdapter;

    #[test]
    fn test_tpm_adapter_new() {
        if let Ok(mut tpm) = TpmAdapter::new("swtpm:path=/tmp/tpmstate/swtpm.sock") {
            let _ = tpm.create_ak();
        }
    }
}
