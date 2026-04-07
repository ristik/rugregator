fn main() {
    #[cfg(feature = "prove")]
    {
        use sp1_build::{build_program_with_args, BuildArgs};

        let args = BuildArgs {
            // Set SP1_BUILD_DOCKER=1 to use Docker for reproducible ELF builds.
            docker: std::env::var("SP1_BUILD_DOCKER").is_ok(),
            output_directory: None,
            elf_name: Some("zk-guest-program".to_string()),
            ..Default::default()
        };
        build_program_with_args(
            // Path is relative to this Cargo.toml (crates/zk-host/).
            "../../zk-guest/program",
            args,
        );
    }
}
