#![cfg(feature = "flate2")]

use russh::compression::{Compress, Compression, Decompress};

const PACKET_TEXTS: [&str; 5] = [
    "冻结应答-ENQ",
    "持续输入一",
    "冻结应答-ENQ",
    "持续输入二",
    "冻结应答-ENQ",
];

fn assert_channel_data_stream(
    compression: Compression,
    cycles: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut encoder = Compress::None;
    let mut decoder = Decompress::None;
    compression.init_compress(&mut encoder);
    compression.init_decompress(&mut decoder);
    let mut compressed = Vec::new();
    let mut output = Vec::new();

    for cycle in 0..cycles {
        for (index, text) in PACKET_TEXTS.iter().enumerate() {
            // RFC 4254 CHANNEL_DATA：类型、channel、SSH string 长度与内容。
            let mut packet = vec![94, 0, 0, 0, 2];
            packet.extend_from_slice(&u32::try_from(text.len())?.to_be_bytes());
            packet.extend_from_slice(text.as_bytes());
            let length = encoder.compress_into(&packet, &mut compressed, 0)?;
            let input = compressed.get(..length).ok_or("压缩长度超出实际缓冲区")?;
            let decoded = decoder.decompress(input, &mut output)?;
            assert_eq!(
                decoded, packet,
                "每包必须完整解出，不向后继包遗留数据：{compression:?}，轮次 {cycle}，包 {index}"
            );
        }
    }
    Ok(())
}

#[test]
fn five_channel_data_packets_are_decoded_completely() -> Result<(), Box<dyn std::error::Error>> {
    for compression in [Compression::Zlib, Compression::ZlibOpenSSH] {
        assert_channel_data_stream(compression, 1)?;
    }
    Ok(())
}

#[test]
fn channel_data_dictionary_cycles_preserve_packet_boundaries(
) -> Result<(), Box<dyn std::error::Error>> {
    for compression in [Compression::Zlib, Compression::ZlibOpenSSH] {
        assert_channel_data_stream(compression, 32)?;
    }
    Ok(())
}
