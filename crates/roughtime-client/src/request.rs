/// Build Roughtime request messages (1024-byte padded, IETF draft-14).

use roughtime_wire::{tags, MessageBuilder};

/// Minimum request size per IETF spec.
pub const REQUEST_SIZE: usize = 1024;

/// Build a 1024-byte padded Roughtime request with the given nonce.
///
/// Layout: VER + NONC + ZZZZ (padding to 1024 bytes).
pub fn build_request(nonce: &[u8; 32]) -> Vec<u8> {
    let mut builder = MessageBuilder::new();
    builder.add_tag(tags::TAG_VER, &tags::VERSION_DRAFT14.to_le_bytes());
    builder.add_tag(tags::TAG_NONC, nonce);

    // Encode without padding first to compute padding size
    let base = builder.encode();
    let needed = REQUEST_SIZE.saturating_sub(base.len());

    // Now rebuild with padding
    if needed > 0 {
        // We need to account for the tag entry overhead when adding ZZZZ.
        // Adding a new tag costs: 4 bytes (offset entry) + 4 bytes (tag entry) = 8 bytes.
        // So the padding value is: needed - 8 bytes overhead.
        // But the base was encoded with 2 tags, re-encoding with 3 tags changes the header.
        // Let's just compute exactly.
        let mut builder2 = MessageBuilder::new();
        builder2.add_tag(tags::TAG_VER, &tags::VERSION_DRAFT14.to_le_bytes());
        builder2.add_tag(tags::TAG_NONC, nonce);
        builder2.add_tag(tags::TAG_ZZZZ, &[]); // empty padding first

        let with_empty_pad = builder2.encode();
        let pad_value_size = REQUEST_SIZE.saturating_sub(with_empty_pad.len());
        let padding = vec![0u8; pad_value_size];

        let mut builder3 = MessageBuilder::new();
        builder3.add_tag(tags::TAG_VER, &tags::VERSION_DRAFT14.to_le_bytes());
        builder3.add_tag(tags::TAG_NONC, nonce);
        builder3.add_tag(tags::TAG_ZZZZ, &padding);

        builder3.encode()
    } else {
        base
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use roughtime_wire::Message;

    #[test]
    fn request_is_1024_bytes() {
        let nonce = [0x42u8; 32];
        let req = build_request(&nonce);
        assert_eq!(req.len(), REQUEST_SIZE);
    }

    #[test]
    fn request_contains_ver_nonc_zzzz() {
        let nonce = [0x42u8; 32];
        let req = build_request(&nonce);
        let msg = Message::parse(&req).unwrap();

        assert!(msg.get_tag(tags::TAG_VER).is_some());
        assert_eq!(msg.get_tag(tags::TAG_NONC).unwrap(), &nonce);
        assert!(msg.get_tag(tags::TAG_ZZZZ).is_some());
    }
}
