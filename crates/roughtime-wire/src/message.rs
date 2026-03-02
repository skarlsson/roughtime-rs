/// Roughtime message encoding and decoding.
///
/// A Roughtime message is a sequence of (tag, value) pairs with the following
/// binary layout:
///
///   [num_tags: u32 LE]
///   [offsets: (num_tags - 1) × u32 LE]   // cumulative byte offsets into values
///   [tags: num_tags × u32 LE]            // tag identifiers, strictly ascending
///   [values: concatenated tag values]    // 4-byte aligned
///
/// Tags must appear in strictly ascending numeric order.

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// Error type for wire format operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    /// Input too short to contain a valid message.
    TooShort,
    /// Number of tags is zero.
    EmptyMessage,
    /// Tag offsets are not monotonically increasing.
    BadOffsets,
    /// Tags are not in strictly ascending order.
    TagsNotSorted,
    /// Offset points beyond the value region.
    OffsetOutOfBounds,
    /// Message size is not 4-byte aligned.
    BadAlignment,
    /// Invalid framing header.
    BadFraming,
}

impl core::fmt::Display for WireError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            WireError::TooShort => write!(f, "message too short"),
            WireError::EmptyMessage => write!(f, "message has zero tags"),
            WireError::BadOffsets => write!(f, "tag offsets not monotonically increasing"),
            WireError::TagsNotSorted => write!(f, "tags not in strictly ascending order"),
            WireError::OffsetOutOfBounds => write!(f, "offset out of bounds"),
            WireError::BadAlignment => write!(f, "message not 4-byte aligned"),
            WireError::BadFraming => write!(f, "invalid framing header"),
        }
    }
}

/// Zero-copy parser for a Roughtime message.
///
/// Borrows the input buffer and provides tag-based lookup.
#[derive(Debug)]
pub struct Message<'a> {
    num_tags: usize,
    tags: &'a [u8],
    offsets: &'a [u8],
    values: &'a [u8],
}

impl<'a> Message<'a> {
    /// Parse a Roughtime message from a byte slice.
    ///
    /// The input must be 4-byte aligned in length.
    pub fn parse(data: &'a [u8]) -> Result<Self, WireError> {
        if data.len() < 4 {
            return Err(WireError::TooShort);
        }
        if data.len() % 4 != 0 {
            return Err(WireError::BadAlignment);
        }

        let num_tags = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if num_tags == 0 {
            return Err(WireError::EmptyMessage);
        }

        // Header size: 4 (num_tags) + 4*(num_tags-1) (offsets) + 4*num_tags (tags)
        let header_size = 4 + 4 * (num_tags.saturating_sub(1)) + 4 * num_tags;
        if data.len() < header_size {
            return Err(WireError::TooShort);
        }

        let offsets_start = 4;
        let offsets_end = 4 + 4 * num_tags.saturating_sub(1);
        let tags_start = offsets_end;
        let tags_end = tags_start + 4 * num_tags;
        let values_start = tags_end;

        let offsets = &data[offsets_start..offsets_end];
        let tags = &data[tags_start..tags_end];
        let values = &data[values_start..];

        // Validate offsets are monotonically increasing
        let mut prev_offset = 0u32;
        for i in 0..num_tags.saturating_sub(1) {
            let off = u32::from_le_bytes([
                offsets[i * 4],
                offsets[i * 4 + 1],
                offsets[i * 4 + 2],
                offsets[i * 4 + 3],
            ]);
            if off < prev_offset {
                return Err(WireError::BadOffsets);
            }
            if off as usize > values.len() {
                return Err(WireError::OffsetOutOfBounds);
            }
            prev_offset = off;
        }

        // Validate tags are strictly ascending
        let mut prev_tag = 0u32;
        for i in 0..num_tags {
            let tag = u32::from_le_bytes([
                tags[i * 4],
                tags[i * 4 + 1],
                tags[i * 4 + 2],
                tags[i * 4 + 3],
            ]);
            if i > 0 && tag <= prev_tag {
                return Err(WireError::TagsNotSorted);
            }
            prev_tag = tag;
        }

        Ok(Message {
            num_tags,
            tags,
            offsets,
            values,
        })
    }

    /// Number of tags in the message.
    pub fn num_tags(&self) -> usize {
        self.num_tags
    }

    /// Look up a tag value by tag ID. Returns `None` if the tag is not present.
    pub fn get_tag(&self, tag: u32) -> Option<&'a [u8]> {
        // Binary search through tags
        let mut lo = 0usize;
        let mut hi = self.num_tags;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let t = self.read_tag(mid);
            if t == tag {
                return Some(self.tag_value(mid));
            } else if t < tag {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        None
    }

    /// Get the tag ID at a given index.
    fn read_tag(&self, idx: usize) -> u32 {
        let off = idx * 4;
        u32::from_le_bytes([
            self.tags[off],
            self.tags[off + 1],
            self.tags[off + 2],
            self.tags[off + 3],
        ])
    }

    /// Get the value slice for a tag at a given index.
    fn tag_value(&self, idx: usize) -> &'a [u8] {
        let start = if idx == 0 {
            0
        } else {
            let off = (idx - 1) * 4;
            u32::from_le_bytes([
                self.offsets[off],
                self.offsets[off + 1],
                self.offsets[off + 2],
                self.offsets[off + 3],
            ]) as usize
        };

        let end = if idx == self.num_tags - 1 {
            self.values.len()
        } else {
            let off = idx * 4;
            u32::from_le_bytes([
                self.offsets[off],
                self.offsets[off + 1],
                self.offsets[off + 2],
                self.offsets[off + 3],
            ]) as usize
        };

        &self.values[start..end]
    }
}

/// Builder for constructing Roughtime messages.
///
/// Tags are added in any order; the builder sorts them before encoding.
#[cfg(feature = "alloc")]
pub struct MessageBuilder {
    tags: Vec<(u32, Vec<u8>)>,
}

#[cfg(feature = "alloc")]
impl MessageBuilder {
    pub fn new() -> Self {
        MessageBuilder { tags: Vec::new() }
    }

    /// Add a tag-value pair. Values are automatically padded to 4-byte alignment.
    pub fn add_tag(&mut self, tag: u32, value: &[u8]) -> &mut Self {
        self.tags.push((tag, value.to_vec()));
        self
    }

    /// Encode the message into a byte vector.
    ///
    /// Tags are sorted by tag value (ascending) before encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut sorted: Vec<(u32, &[u8])> =
            self.tags.iter().map(|(t, v)| (*t, v.as_slice())).collect();
        sorted.sort_by_key(|(t, _)| *t);

        let num_tags = sorted.len();

        // Compute padded value sizes (each value 4-byte aligned)
        let padded_sizes: Vec<usize> = sorted
            .iter()
            .map(|(_, v)| {
                let len = v.len();
                (len + 3) & !3 // round up to 4-byte boundary
            })
            .collect();

        // Compute cumulative offsets
        let mut cumulative = Vec::with_capacity(num_tags);
        let mut acc = 0usize;
        for &ps in &padded_sizes {
            acc += ps;
            cumulative.push(acc as u32);
        }

        // Header size
        let header_size = 4 + 4 * num_tags.saturating_sub(1) + 4 * num_tags;
        let values_size: usize = padded_sizes.iter().sum();
        let total_size = header_size + values_size;

        let mut buf = Vec::with_capacity(total_size);

        // num_tags
        buf.extend_from_slice(&(num_tags as u32).to_le_bytes());

        // offsets (num_tags - 1 entries; offset[i] = cumulative end of value[i])
        // offset[i] gives the start of value[i+1], which is the end of value[i]
        for i in 0..num_tags.saturating_sub(1) {
            buf.extend_from_slice(&cumulative[i].to_le_bytes());
        }

        // tags
        for (tag, _) in &sorted {
            buf.extend_from_slice(&tag.to_le_bytes());
        }

        // values (padded)
        for (i, (_, v)) in sorted.iter().enumerate() {
            buf.extend_from_slice(v);
            let padding = padded_sizes[i] - v.len();
            for _ in 0..padding {
                buf.push(0);
            }
        }

        buf
    }
}

#[cfg(feature = "alloc")]
impl Default for MessageBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tags::*;

    #[test]
    fn roundtrip_single_tag() {
        let mut builder = MessageBuilder::new();
        builder.add_tag(TAG_VER, &VERSION_DRAFT14.to_le_bytes());
        let encoded = builder.encode();

        let msg = Message::parse(&encoded).unwrap();
        assert_eq!(msg.num_tags(), 1);

        let ver = msg.get_tag(TAG_VER).unwrap();
        assert_eq!(ver.len(), 4);
        let ver_val = u32::from_le_bytes([ver[0], ver[1], ver[2], ver[3]]);
        assert_eq!(ver_val, VERSION_DRAFT14);
    }

    #[test]
    fn roundtrip_multiple_tags() {
        let nonce = [0xABu8; 32];
        let padding = [0u8; 944];

        let mut builder = MessageBuilder::new();
        builder.add_tag(TAG_VER, &VERSION_DRAFT14.to_le_bytes());
        builder.add_tag(TAG_NONC, &nonce);
        builder.add_tag(TAG_ZZZZ, &padding);

        let encoded = builder.encode();
        let msg = Message::parse(&encoded).unwrap();
        assert_eq!(msg.num_tags(), 3);

        let ver = msg.get_tag(TAG_VER).unwrap();
        assert_eq!(
            u32::from_le_bytes([ver[0], ver[1], ver[2], ver[3]]),
            VERSION_DRAFT14
        );

        let n = msg.get_tag(TAG_NONC).unwrap();
        assert_eq!(n, &nonce);

        let z = msg.get_tag(TAG_ZZZZ).unwrap();
        assert_eq!(z.len(), 944);
    }

    #[test]
    fn tags_sorted_ascending() {
        // Add tags out of order; builder should sort them
        let mut builder = MessageBuilder::new();
        builder.add_tag(TAG_ZZZZ, &[0u8; 4]);
        builder.add_tag(TAG_VER, &VERSION_DRAFT14.to_le_bytes());
        builder.add_tag(TAG_NONC, &[1u8; 32]);

        let encoded = builder.encode();
        let msg = Message::parse(&encoded).unwrap();
        assert_eq!(msg.num_tags(), 3);

        // All tags should be retrievable
        assert!(msg.get_tag(TAG_VER).is_some());
        assert!(msg.get_tag(TAG_NONC).is_some());
        assert!(msg.get_tag(TAG_ZZZZ).is_some());
    }

    #[test]
    fn missing_tag_returns_none() {
        let mut builder = MessageBuilder::new();
        builder.add_tag(TAG_VER, &VERSION_DRAFT14.to_le_bytes());
        let encoded = builder.encode();
        let msg = Message::parse(&encoded).unwrap();
        assert!(msg.get_tag(TAG_NONC).is_none());
    }

    #[test]
    fn empty_message_rejected() {
        let data = 0u32.to_le_bytes();
        assert!(matches!(Message::parse(&data), Err(WireError::EmptyMessage)));
    }

    #[test]
    fn too_short_rejected() {
        assert!(matches!(Message::parse(&[0, 0]), Err(WireError::TooShort)));
    }

    #[test]
    fn bad_alignment_rejected() {
        assert!(matches!(
            Message::parse(&[1, 0, 0, 0, 0]),
            Err(WireError::BadAlignment)
        ));
    }

    #[test]
    fn nested_message_roundtrip() {
        // Simulate SREP containing MIDP + RADI + ROOT
        let midp: u64 = 1700000000;
        let radi: u32 = 10;
        let root = [0xBBu8; 64];

        let mut srep_builder = MessageBuilder::new();
        srep_builder.add_tag(TAG_MIDP, &midp.to_le_bytes());
        srep_builder.add_tag(TAG_RADI, &radi.to_le_bytes());
        srep_builder.add_tag(TAG_ROOT, &root);
        let srep_bytes = srep_builder.encode();

        // Wrap in outer message
        let sig = [0xCC; 64];
        let mut outer = MessageBuilder::new();
        outer.add_tag(TAG_SIG, &sig);
        outer.add_tag(TAG_SREP, &srep_bytes);
        let encoded = outer.encode();

        let outer_msg = Message::parse(&encoded).unwrap();
        let srep_data = outer_msg.get_tag(TAG_SREP).unwrap();
        let srep_msg = Message::parse(srep_data).unwrap();

        let midp_bytes = srep_msg.get_tag(TAG_MIDP).unwrap();
        let parsed_midp = u64::from_le_bytes(midp_bytes.try_into().unwrap());
        assert_eq!(parsed_midp, 1700000000);

        let root_bytes = srep_msg.get_tag(TAG_ROOT).unwrap();
        assert_eq!(root_bytes, &root);
    }
}
