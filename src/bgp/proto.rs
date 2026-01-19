pub mod apipb {
    // GoBGP v4.x uses "api" package name
    // Allow dead code - we only use a subset of the generated GoBGP API
    // Allow enum variant naming from proto definitions
    #![allow(dead_code)]
    #![allow(clippy::enum_variant_names)]
    #![allow(clippy::large_enum_variant)]
    tonic::include_proto!("api");
}
