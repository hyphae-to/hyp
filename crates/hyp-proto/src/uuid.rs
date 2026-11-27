//! Pure RFC 9562 UUID formatting; callers own entropy and failure policy.

/// Sets the RFC 9562 version-4 and variant bits and formats lowercase UUID bytes.
pub fn format_uuid_v4(mut bytes: [u8; 16]) -> String {
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    )
}

#[cfg(test)]
mod tests {
    use super::format_uuid_v4;

    #[test]
    fn uuid_v4_wire_vectors_preserve_random_bits_and_set_version_and_variant() {
        for (bytes, expected) in [
            ([0; 16], "00000000-0000-4000-8000-000000000000"),
            ([0xff; 16], "ffffffff-ffff-4fff-bfff-ffffffffffff"),
            (
                [
                    0x91, 0x91, 0x08, 0xf7, 0x52, 0xd1, 0xf3, 0x20, 0xdb, 0xac, 0xf8, 0x47, 0xdb,
                    0x41, 0x48, 0xa8,
                ],
                "919108f7-52d1-4320-9bac-f847db4148a8",
            ),
        ] {
            assert_eq!(format_uuid_v4(bytes), expected);
        }
    }
}
