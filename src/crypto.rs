//! SO 文件解密模块
//! 
//! 使用 ChaCha20-Poly1305 AEAD 加密
//! 格式: [ 12 bytes nonce ][ ciphertext + 16 bytes tag ]

use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, 
    aead::{Aead, generic_array::GenericArray},
};
use zeroize::Zeroize;

// 密钥常量 - 编译时由 build.rs 生成
// 使用 XOR 混淆存储，运行时还原
mod crypto_key {
    include!(concat!(env!("OUT_DIR"), "/crypto_key.rs"));
}

/// 解密 SO 文件
/// 
/// # Arguments
/// * `encrypted_data` - 加密数据 (nonce + ciphertext + tag)
/// 
/// # Returns
/// * `Ok(Vec<u8>)` - 解密后的 SO 数据
/// * `Err(String)` - 解密失败原因
pub fn decrypt_so(encrypted_data: &[u8]) -> Result<Vec<u8>, String> {
    const NONCE_SIZE: usize = 12;
    const TAG_SIZE: usize = 16;
    const MIN_SIZE: usize = NONCE_SIZE + TAG_SIZE + 1;
    
    if encrypted_data.len() < MIN_SIZE {
        return Err(format!(
            "Encrypted data too short: {} bytes (min {})", 
            encrypted_data.len(), MIN_SIZE
        ));
    }
    
    // 1. 提取 nonce 和密文
    let nonce_bytes = &encrypted_data[..NONCE_SIZE];
    let ciphertext = &encrypted_data[NONCE_SIZE..];
    
    // 2. 还原密钥 (XOR 解混淆)
    let mut key = derive_key();
    
    // 3. 创建 cipher 并解密
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&key));
    let nonce = GenericArray::from_slice(nonce_bytes);
    
    let result = cipher.decrypt(nonce, ciphertext)
        .map_err(|e| format!("Decryption failed: {:?}", e));
    
    // 4. 安全清除密钥
    key.zeroize();
    
    match &result {
        Ok(data) => {
            // 验证解密后是有效的 ELF
            if data.len() >= 4 && &data[0..4] == b"\x7fELF" {
                crate::println!("[Crypto] Decrypted SO: {} bytes", data.len());
            } else {
                return Err("Decrypted data is not a valid ELF file".to_string());
            }
        }
        Err(e) => {
            crate::println!("[Crypto] Decryption error: {}", e);
        }
    }
    
    result
}

/// 从混淆的密钥数据中派生实际密钥
fn derive_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    
    // XOR 还原: key = KEY_PART_A ^ KEY_PART_B
    for i in 0..32 {
        key[i] = crypto_key::KEY_PART_A[i] ^ crypto_key::KEY_PART_B[i];
    }
    
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_decrypt_too_short() {
        let result = decrypt_so(&[0u8; 10]);
        assert!(result.is_err());
    }
}
