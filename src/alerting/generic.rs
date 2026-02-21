use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;

use super::Alert;

type HmacSha256 = Hmac<Sha256>;

pub async fn send(
    client: &reqwest::Client,
    url: &str,
    secret: Option<&str>,
    headers: &HashMap<String, String>,
    alert: &Alert,
) -> Result<(), String> {
    let body =
        serde_json::to_vec(alert).map_err(|e| format!("json serialization failed: {}", e))?;

    let mut request = client
        .post(url)
        .header("Content-Type", "application/json")
        .header("User-Agent", "prefixd-webhook/1.0");

    // HMAC-SHA256 signature
    if let Some(secret) = secret {
        let signature = compute_signature(secret.as_bytes(), &body);
        request = request.header("X-Prefixd-Signature", format!("sha256={}", signature));
    }

    for (key, value) in headers {
        request = request.header(key, value);
    }

    let response = request
        .body(body)
        .send()
        .await
        .map_err(|e| format!("webhook request failed: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("webhook returned {} — {}", status, body));
    }

    Ok(())
}

fn compute_signature(secret: &[u8], body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC can take key of any size");
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_signature() {
        let sig = compute_signature(b"my-secret", b"hello world");
        assert_eq!(sig.len(), 64); // SHA-256 hex output
        // Verify deterministic
        let sig2 = compute_signature(b"my-secret", b"hello world");
        assert_eq!(sig, sig2);
        // Different secret = different signature
        let sig3 = compute_signature(b"other-secret", b"hello world");
        assert_ne!(sig, sig3);
    }
}
