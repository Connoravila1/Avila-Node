//! Narrow safe wrapper around Bitcoin Core's 8-way AVX2 SHA256D64 kernel.
//!
//! The function returns `None` on CPUs without AVX2 or when the crate was
//! built for a non-x86_64 target. Callers then use their existing scalar
//! SHA256D64 implementation.

#[cfg(avila_sha256d64_avx2)]
unsafe extern "C" {
    fn avila_sha256d64_8way(out: *mut u8, input: *const u8);
}

/// Hashes eight independent 64-byte messages with SHA256d when AVX2 is
/// available. Each input element is a contiguous `left || right` pair of
/// 32-byte hashes. Inputs and outputs use the byte order used by SHA-256.
#[must_use]
pub fn try_sha256d64_8(input: &[[[u8; 32]; 2]]) -> Option<[[u8; 32]; 8]> {
    if input.len() != 8 {
        return None;
    }

    #[cfg(avila_sha256d64_avx2)]
    {
        if !std::is_x86_feature_detected!("avx2") {
            return None;
        }

        let mut output = [[0u8; 32]; 8];
        // SAFETY: the length check establishes exactly eight pairs. Nested
        // arrays have contiguous layout, so they provide the 8 * 64 input
        // bytes expected by Core's kernel. The runtime feature check above
        // ensures the target CPU supports every instruction in the TU.
        unsafe {
            avila_sha256d64_8way(output.as_mut_ptr().cast(), input.as_ptr().cast());
        }
        Some(output)
    }

    #[cfg(not(avila_sha256d64_avx2))]
    {
        let _ = input;
        None
    }
}
