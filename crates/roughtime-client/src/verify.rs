/// Roughtime response verification: Ed25519 signatures, Merkle proofs, delegation chain.

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha512};

use roughtime_wire::{tags, Message, WireError};

/// Error type for verification failures.
#[derive(Debug)]
pub enum VerifyError {
    /// Wire format error.
    Wire(WireError),
    /// Missing required tag.
    MissingTag(&'static str),
    /// Invalid version.
    BadVersion(u32),
    /// Ed25519 signature verification failed.
    BadSignature(&'static str),
    /// Merkle proof verification failed.
    BadMerkleProof,
    /// Invalid field length.
    BadFieldLength(&'static str),
    /// Invalid public key encoding.
    BadPublicKey,
}

impl core::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VerifyError::Wire(e) => write!(f, "wire error: {e}"),
            VerifyError::MissingTag(t) => write!(f, "missing tag: {t}"),
            VerifyError::BadVersion(v) => write!(f, "bad version: 0x{v:08x}"),
            VerifyError::BadSignature(ctx) => write!(f, "bad signature: {ctx}"),
            VerifyError::BadMerkleProof => write!(f, "merkle proof verification failed"),
            VerifyError::BadFieldLength(t) => write!(f, "bad field length: {t}"),
            VerifyError::BadPublicKey => write!(f, "invalid public key"),
        }
    }
}

impl From<WireError> for VerifyError {
    fn from(e: WireError) -> Self {
        VerifyError::Wire(e)
    }
}

/// Result of a successful response verification.
#[derive(Debug)]
pub struct VerifiedTime {
    pub midpoint: u64,
    pub radius: u32,
}

/// Verify a Roughtime response against a server's long-term public key and the
/// nonce that was used in the request.
///
/// Verification steps:
/// 1. Parse top-level message → extract CERT, SIG, SREP, INDX, PATH
/// 2. Parse CERT → extract DELE sub-message and DELE signature
/// 3. Verify DELE signature (long-term key signs context || DELE)
/// 4. Parse DELE → extract PUBK (delegated public key)
/// 5. Verify SREP signature (delegated key signs context || SREP)
/// 6. Parse SREP → extract ROOT, MIDP, RADI
/// 7. Verify Merkle proof: leaf(nonce) + PATH + INDX → ROOT
/// 8. Return verified midpoint and radius.
pub fn verify_response(
    response: &[u8],
    nonce: &[u8; 32],
    server_pubkey: &[u8; 32],
) -> Result<VerifiedTime, VerifyError> {
    let msg = Message::parse(response)?;

    // Check version if present
    if let Some(ver_bytes) = msg.get_tag(tags::TAG_VER) {
        if ver_bytes.len() >= 4 {
            let ver = u32::from_le_bytes([ver_bytes[0], ver_bytes[1], ver_bytes[2], ver_bytes[3]]);
            if ver != tags::VERSION_DRAFT14 {
                return Err(VerifyError::BadVersion(ver));
            }
        }
    }

    // Extract top-level fields
    let cert_bytes = msg
        .get_tag(tags::TAG_CERT)
        .ok_or(VerifyError::MissingTag("CERT"))?;
    let srep_sig_bytes = msg
        .get_tag(tags::TAG_SIG)
        .ok_or(VerifyError::MissingTag("SIG"))?;
    let srep_bytes = msg
        .get_tag(tags::TAG_SREP)
        .ok_or(VerifyError::MissingTag("SREP"))?;
    let indx_bytes = msg
        .get_tag(tags::TAG_INDX)
        .ok_or(VerifyError::MissingTag("INDX"))?;

    // PATH is optional (absent when Merkle tree has exactly one leaf)
    let path_bytes = msg.get_tag(tags::TAG_PATH).unwrap_or(&[]);

    // Validate field lengths
    if srep_sig_bytes.len() != 64 {
        return Err(VerifyError::BadFieldLength("SIG"));
    }
    if indx_bytes.len() != 4 {
        return Err(VerifyError::BadFieldLength("INDX"));
    }
    if path_bytes.len() % 64 != 0 {
        return Err(VerifyError::BadFieldLength("PATH"));
    }

    // Parse CERT → DELE + SIG
    let cert_msg = Message::parse(cert_bytes)?;
    let dele_bytes = cert_msg
        .get_tag(tags::TAG_DELE)
        .ok_or(VerifyError::MissingTag("DELE in CERT"))?;
    let dele_sig_bytes = cert_msg
        .get_tag(tags::TAG_SIG)
        .ok_or(VerifyError::MissingTag("SIG in CERT"))?;

    if dele_sig_bytes.len() != 64 {
        return Err(VerifyError::BadFieldLength("DELE SIG"));
    }

    // Verify DELE signature: long-term key signs (context || DELE)
    let server_key = VerifyingKey::from_bytes(server_pubkey)
        .map_err(|_| VerifyError::BadPublicKey)?;
    let dele_sig = Signature::from_bytes(dele_sig_bytes.try_into().unwrap());

    let mut dele_signed_data = Vec::with_capacity(tags::SIG_CONTEXT_DELE.len() + dele_bytes.len());
    dele_signed_data.extend_from_slice(tags::SIG_CONTEXT_DELE);
    dele_signed_data.extend_from_slice(dele_bytes);

    server_key
        .verify_strict(&dele_signed_data, &dele_sig)
        .map_err(|_| VerifyError::BadSignature("DELE"))?;

    // Parse DELE → PUBK (delegated public key)
    let dele_msg = Message::parse(dele_bytes)?;
    let pubk_bytes = dele_msg
        .get_tag(tags::TAG_PUBK)
        .ok_or(VerifyError::MissingTag("PUBK in DELE"))?;
    if pubk_bytes.len() != 32 {
        return Err(VerifyError::BadFieldLength("PUBK"));
    }

    // Verify SREP signature: delegated key signs (context || SREP)
    let delegated_key = VerifyingKey::from_bytes(pubk_bytes.try_into().unwrap())
        .map_err(|_| VerifyError::BadPublicKey)?;
    let srep_sig = Signature::from_bytes(srep_sig_bytes.try_into().unwrap());

    let mut srep_signed_data = Vec::with_capacity(tags::SIG_CONTEXT_SREP.len() + srep_bytes.len());
    srep_signed_data.extend_from_slice(tags::SIG_CONTEXT_SREP);
    srep_signed_data.extend_from_slice(srep_bytes);

    delegated_key
        .verify_strict(&srep_signed_data, &srep_sig)
        .map_err(|_| VerifyError::BadSignature("SREP"))?;

    // Parse SREP → ROOT, MIDP, RADI
    let srep_msg = Message::parse(srep_bytes)?;
    let root_bytes = srep_msg
        .get_tag(tags::TAG_ROOT)
        .ok_or(VerifyError::MissingTag("ROOT in SREP"))?;
    let midp_bytes = srep_msg
        .get_tag(tags::TAG_MIDP)
        .ok_or(VerifyError::MissingTag("MIDP in SREP"))?;
    let radi_bytes = srep_msg
        .get_tag(tags::TAG_RADI)
        .ok_or(VerifyError::MissingTag("RADI in SREP"))?;

    if root_bytes.len() != 64 {
        return Err(VerifyError::BadFieldLength("ROOT"));
    }
    if midp_bytes.len() != 8 {
        return Err(VerifyError::BadFieldLength("MIDP"));
    }
    if radi_bytes.len() != 4 {
        return Err(VerifyError::BadFieldLength("RADI"));
    }

    // Verify Merkle proof
    let index = u32::from_le_bytes(indx_bytes.try_into().unwrap());
    verify_merkle_proof(nonce, index, path_bytes, root_bytes)?;

    let midpoint = u64::from_le_bytes(midp_bytes.try_into().unwrap());
    let radius = u32::from_le_bytes(radi_bytes.try_into().unwrap());

    Ok(VerifiedTime { midpoint, radius })
}

/// Verify a Roughtime response's Ed25519 signatures only (no Merkle proof).
///
/// Used for offline/bag mode where we have genuine server signatures but
/// no nonce binding.
pub fn verify_response_signatures_only(
    response: &[u8],
    server_pubkey: &[u8; 32],
) -> Result<VerifiedTime, VerifyError> {
    let msg = Message::parse(response)?;

    // Extract top-level fields
    let cert_bytes = msg
        .get_tag(tags::TAG_CERT)
        .ok_or(VerifyError::MissingTag("CERT"))?;
    let srep_sig_bytes = msg
        .get_tag(tags::TAG_SIG)
        .ok_or(VerifyError::MissingTag("SIG"))?;
    let srep_bytes = msg
        .get_tag(tags::TAG_SREP)
        .ok_or(VerifyError::MissingTag("SREP"))?;

    if srep_sig_bytes.len() != 64 {
        return Err(VerifyError::BadFieldLength("SIG"));
    }

    // Parse CERT → DELE + SIG
    let cert_msg = Message::parse(cert_bytes)?;
    let dele_bytes = cert_msg
        .get_tag(tags::TAG_DELE)
        .ok_or(VerifyError::MissingTag("DELE in CERT"))?;
    let dele_sig_bytes = cert_msg
        .get_tag(tags::TAG_SIG)
        .ok_or(VerifyError::MissingTag("SIG in CERT"))?;

    if dele_sig_bytes.len() != 64 {
        return Err(VerifyError::BadFieldLength("DELE SIG"));
    }

    // Verify DELE signature
    let server_key =
        VerifyingKey::from_bytes(server_pubkey).map_err(|_| VerifyError::BadPublicKey)?;
    let dele_sig = Signature::from_bytes(dele_sig_bytes.try_into().unwrap());

    let mut dele_signed_data = Vec::with_capacity(tags::SIG_CONTEXT_DELE.len() + dele_bytes.len());
    dele_signed_data.extend_from_slice(tags::SIG_CONTEXT_DELE);
    dele_signed_data.extend_from_slice(dele_bytes);

    server_key
        .verify_strict(&dele_signed_data, &dele_sig)
        .map_err(|_| VerifyError::BadSignature("DELE"))?;

    // Parse DELE → PUBK
    let dele_msg = Message::parse(dele_bytes)?;
    let pubk_bytes = dele_msg
        .get_tag(tags::TAG_PUBK)
        .ok_or(VerifyError::MissingTag("PUBK in DELE"))?;
    if pubk_bytes.len() != 32 {
        return Err(VerifyError::BadFieldLength("PUBK"));
    }

    // Verify SREP signature
    let delegated_key = VerifyingKey::from_bytes(pubk_bytes.try_into().unwrap())
        .map_err(|_| VerifyError::BadPublicKey)?;
    let srep_sig = Signature::from_bytes(srep_sig_bytes.try_into().unwrap());

    let mut srep_signed_data = Vec::with_capacity(tags::SIG_CONTEXT_SREP.len() + srep_bytes.len());
    srep_signed_data.extend_from_slice(tags::SIG_CONTEXT_SREP);
    srep_signed_data.extend_from_slice(srep_bytes);

    delegated_key
        .verify_strict(&srep_signed_data, &srep_sig)
        .map_err(|_| VerifyError::BadSignature("SREP"))?;

    // Parse SREP → MIDP, RADI
    let srep_msg = Message::parse(srep_bytes)?;
    let midp_bytes = srep_msg
        .get_tag(tags::TAG_MIDP)
        .ok_or(VerifyError::MissingTag("MIDP in SREP"))?;
    let radi_bytes = srep_msg
        .get_tag(tags::TAG_RADI)
        .ok_or(VerifyError::MissingTag("RADI in SREP"))?;

    if midp_bytes.len() != 8 {
        return Err(VerifyError::BadFieldLength("MIDP"));
    }
    if radi_bytes.len() != 4 {
        return Err(VerifyError::BadFieldLength("RADI"));
    }

    let midpoint = u64::from_le_bytes(midp_bytes.try_into().unwrap());
    let radius = u32::from_le_bytes(radi_bytes.try_into().unwrap());

    Ok(VerifiedTime { midpoint, radius })
}

/// Verify a Merkle inclusion proof.
///
/// Roughtime uses SHA-512:
///   leaf = SHA-512(0x00 || nonce)
///   node = SHA-512(0x01 || left || right)
///
/// PATH contains sibling hashes (64 bytes each).
/// INDX determines left/right placement at each level.
fn verify_merkle_proof(
    nonce: &[u8; 32],
    index: u32,
    path: &[u8],
    expected_root: &[u8],
) -> Result<(), VerifyError> {
    let num_levels = path.len() / 64;

    // Compute leaf hash: SHA-512(0x00 || nonce)
    let mut hasher = Sha512::new();
    hasher.update([0x00]);
    hasher.update(nonce);
    let mut current: [u8; 64] = hasher.finalize().into();

    let mut idx = index;

    for level in 0..num_levels {
        let sibling = &path[level * 64..(level + 1) * 64];
        let mut hasher = Sha512::new();
        hasher.update([0x01]);
        if idx & 1 == 0 {
            // Current is left child
            hasher.update(current);
            hasher.update(sibling);
        } else {
            // Current is right child
            hasher.update(sibling);
            hasher.update(current);
        }
        current = hasher.finalize().into();
        idx >>= 1;
    }

    if current.as_slice() == expected_root {
        Ok(())
    } else {
        Err(VerifyError::BadMerkleProof)
    }
}

/// Extract midpoint and radius from a raw response without full verification.
/// Used for display purposes when full verification is not needed.
pub fn extract_time(response: &[u8]) -> Result<VerifiedTime, VerifyError> {
    let msg = Message::parse(response)?;
    let srep_bytes = msg
        .get_tag(tags::TAG_SREP)
        .ok_or(VerifyError::MissingTag("SREP"))?;
    let srep_msg = Message::parse(srep_bytes)?;
    let midp_bytes = srep_msg
        .get_tag(tags::TAG_MIDP)
        .ok_or(VerifyError::MissingTag("MIDP"))?;
    let radi_bytes = srep_msg
        .get_tag(tags::TAG_RADI)
        .ok_or(VerifyError::MissingTag("RADI"))?;

    if midp_bytes.len() != 8 {
        return Err(VerifyError::BadFieldLength("MIDP"));
    }
    if radi_bytes.len() != 4 {
        return Err(VerifyError::BadFieldLength("RADI"));
    }

    Ok(VerifiedTime {
        midpoint: u64::from_le_bytes(midp_bytes.try_into().unwrap()),
        radius: u32::from_le_bytes(radi_bytes.try_into().unwrap()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkle_single_leaf() {
        // When there's only one nonce, PATH is empty and the leaf IS the root
        let nonce = [0x42u8; 32];
        let mut hasher = Sha512::new();
        hasher.update([0x00]);
        hasher.update(nonce);
        let root: [u8; 64] = hasher.finalize().into();

        assert!(verify_merkle_proof(&nonce, 0, &[], &root).is_ok());
    }

    #[test]
    fn merkle_two_leaves() {
        let nonce_a = [0x01u8; 32];
        let nonce_b = [0x02u8; 32];

        // leaf_a = SHA-512(0x00 || nonce_a)
        let mut h = Sha512::new();
        h.update([0x00]);
        h.update(nonce_a);
        let leaf_a: [u8; 64] = h.finalize().into();

        // leaf_b = SHA-512(0x00 || nonce_b)
        let mut h = Sha512::new();
        h.update([0x00]);
        h.update(nonce_b);
        let leaf_b: [u8; 64] = h.finalize().into();

        // root = SHA-512(0x01 || leaf_a || leaf_b)
        let mut h = Sha512::new();
        h.update([0x01]);
        h.update(leaf_a);
        h.update(leaf_b);
        let root: [u8; 64] = h.finalize().into();

        // Verify nonce_a at index 0, sibling = leaf_b
        assert!(verify_merkle_proof(&nonce_a, 0, &leaf_b, &root).is_ok());

        // Verify nonce_b at index 1, sibling = leaf_a
        assert!(verify_merkle_proof(&nonce_b, 1, &leaf_a, &root).is_ok());

        // Wrong index should fail
        assert!(verify_merkle_proof(&nonce_a, 1, &leaf_b, &root).is_err());
    }
}
