fn main() {
    let mut config = prost_build::Config::new();
    config.protoc_executable(
        protoc_bin_vendored::protoc_bin_path().expect("failed to locate vendored protoc"),
    );
    config
        .compile_protos(&["proto/sysknife/v1/sysknife.proto"], &["proto"])
        .expect("failed to compile sysknife proto");
}
