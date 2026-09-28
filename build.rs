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

    // rustbgpd controller API (ADR 023). Opt-in while both speakers coexist; the
    // proto is vendored from rustbgpd and is self-contained apart from
    // google/protobuf/field_mask.proto, which prost-build resolves itself.
    if std::env::var_os("CARGO_FEATURE_BGP_RUSTBGPD").is_some() {
        tonic_prost_build::configure()
            .build_server(false)
            .compile_protos(&["proto/rustbgpd.proto"], &["proto/"])?;
    }

    Ok(())
}
