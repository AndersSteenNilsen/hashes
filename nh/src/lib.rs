
use digest::block_buffer::Eager;
use digest::consts::{U1024, U8};
use digest::core_api::{
    Block, BlockSizeUser, BufferKindUser, CoreWrapper, FixedOutputCore, UpdateCore,
};
use digest::crypto_common::{Key, KeyInit, KeySizeUser};
use digest::typenum::Unsigned;
use digest::OutputSizeUser;

pub struct NhCore {
    key: [u8; 1024],
    y: [u8; 8],
}

pub type Nh = CoreWrapper<NhCore>;


fn to_u32_le(chunk: &[u8]) -> u32 {
    u32::from_le_bytes(chunk.try_into().expect("slice with incorrect length"))
}

impl NhCore {
    fn compress(&mut self, message_blocks: &[Block<Self>]) {
        let t = message_blocks.len() / 4;

        let m_chunks: Vec<u32> = message_blocks
            .iter()
            .flat_map(|block| block.chunks(4).map(to_u32_le))
            .collect();
        let k_chunks: Vec<u32> = self.key.chunks(4).map(to_u32_le).collect();

        let mut y = 0u64;

        for i in (0..t).step_by(8) {
            y = y.wrapping_add(
                (m_chunks[i].wrapping_add(k_chunks[i]) as u64)
                    .wrapping_mul(m_chunks[i + 4].wrapping_add(k_chunks[i + 4]) as u64),
            );
            y = y.wrapping_add(
                (m_chunks[i + 1].wrapping_add(k_chunks[i + 1]) as u64)
                    .wrapping_mul(m_chunks[i + 5].wrapping_add(k_chunks[i + 5]) as u64),
            );
            y = y.wrapping_add(
                (m_chunks[i + 2].wrapping_add(k_chunks[i + 2]) as u64)
                    .wrapping_mul(m_chunks[i + 6].wrapping_add(k_chunks[i + 6]) as u64),
            );
            y = y.wrapping_add(
                (m_chunks[i + 3].wrapping_add(k_chunks[i + 3]) as u64)
                    .wrapping_mul(m_chunks[i + 7].wrapping_add(k_chunks[i + 7]) as u64),
            );
        }
        self.y = y.to_le_bytes()[..8]
            .try_into()
            .expect("slice with incorrect length")
    }
}

impl BlockSizeUser for NhCore {
    fn block_size() -> usize {
        8usize
    }

    type BlockSize = U8;
}

impl KeySizeUser for NhCore {
    type KeySize = U1024;

    fn key_size() -> usize {
        Self::KeySize::USIZE
    }
}

impl KeyInit for NhCore {
    fn new(key: &Key<Self>) -> Self {
        Self {
            key: key
                .as_slice()
                .try_into()
                .expect("Key needs to be 1024 bytes."),
            y: [0; 8],
        }
    }
}

impl FixedOutputCore for NhCore {
    fn finalize_fixed_core(
        &mut self,
        _buffer: &mut digest::core_api::Buffer<Self>,
        out: &mut digest::Output<Self>,
    ) {
        out.copy_from_slice(&self.y)
    }
}

impl BufferKindUser for NhCore {
    type BufferKind = Eager;
}

impl UpdateCore for NhCore {
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        self.compress(blocks);
    }
}

impl OutputSizeUser for NhCore {
    type OutputSize = U8;

    fn output_size() -> usize {
        Self::OutputSize::USIZE
    }
}
