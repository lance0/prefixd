fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_prost_build::compile_protos("proto/gobgp.proto")?;
    tonic_prost_build::compile_protos("proto/attribute.proto")?;
    Ok(())
}
