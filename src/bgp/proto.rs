pub mod apipb {
    // GoBGP v4.x uses "api" package name
    // Allow dead code - we only use a subset of the generated GoBGP API
    #![allow(dead_code)]
    tonic::include_proto!("api");
}
