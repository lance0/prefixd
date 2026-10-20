fn main() -> Result<(), Box<dyn std::error::Error>> {
    // GoBGP v4.2.0 proto files
    tonic_prost_build::configure()
        .build_server(false) // We only need client
        .compile_protos(
            &[
                "proto/gobgp.proto",
                "proto/attribute.proto",
                "proto/capability.proto",
                "proto/common.proto",
                "proto/extcom.proto",
                "proto/nlri.proto",
            ],
            &["proto/"],
        )?;

    // rustbgpd controller API (ADR 025). The proto is a pinned rustbgpd release
    // asset (see src/bgp/rustbgpd_proto.rs) and is self-contained apart from
    // google/protobuf/field_mask.proto, which prost-build resolves itself.
    if std::env::var_os("CARGO_FEATURE_BGP_RUSTBGPD").is_some() {
        tonic_prost_build::configure()
            .build_server(std::env::var_os("CARGO_FEATURE_TEST_UTILS").is_some())
            .generate_default_stubs(true)
            .compile_protos(&["proto/rustbgpd.proto"], &["proto/"])?;
    }

    Ok(())
}
