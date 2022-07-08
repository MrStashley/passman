use openssl::symm::{encrypt_aead, decrypt_aead, Cipher};
use openssl::rand::rand_bytes;

use argon2::Argon2;


// hexdumps a buffer
pub fn hexdump(key: &[u8]) {
    for i in 0..key.len() {
        print!("{:0>2X} ", key[i]);
    }
    println!();
}

pub fn chardump(buf: &[u8]) {
    for i in 0..buf.len() {
        print!("{}", buf[i] as char);
    }

    println!();
}

// generates aes key from openssl random bytes
fn fill_buf_with_rand_bytes(key_buf: &mut [u8]) {

    rand_bytes(key_buf).unwrap();
    
}

pub fn memcpy_safe(dest: &mut [u8], src: &[u8]) {
    let src_len = src.len();
    let dest_len = dest.len();
    if(src_len != dest_len) {
        println!("memcpy_safe found src and dest do not have the same length, truncating {}, {}", src_len, dest_len);
    }

    for i in 0..dest_len {
        if i < src_len {
            dest[i] = src[i];
        } else {
            break;
        }
    }
    
}

pub fn memcpy_safe_from_src_range(dest: &mut [u8], src: &[u8], low: usize, high: usize) {
    let src_len = src.len();
    let dest_len = dest.len();
    if(src_len < high) {
        println!("memcpy_safe_range found src_len is not long enough, terminating");
        return;
    } else if (dest_len < high - low) {
        println!("Memcpy_safe_range found dest_len is not long enough, truncating");
    }

    let mut dest_index = 0;

    for i in low..high {
        if(i < src_len){
            dest[dest_index] = src[i];
            dest_index+=1;
            if(dest_index >= dest_len) {
                break;
            }
        } else {
            break;
        }
    }

    
}

// memcpy but adds a null byte to the end of the values copied
// truncates string if not enough space is available
fn strcpy_safe(dest: &mut [u8], src: &[u8]) {
    let src_len = src.len();
    for i in 0..dest.len()-1 {
        if i < src_len {
            dest[i] = src[i];
        } else {
            dest[i] = 0;
            break;
        }
    }

    dest[dest.len()-1] = 0;
}

fn encrypt(key: &[u8], iv: &mut [u8], plaintext: &[u8], ciphertext: &mut [u8], tag: &mut [u8]) -> Result<i8, String> {
    let mut tag_buf = [0u8; 16];

    fill_buf_with_rand_bytes(iv);

    let ctext_out = match encrypt_aead(
        Cipher::aes_256_gcm(),
        &key,
        Some(&iv), 
        &[3u8;1],
        plaintext,
        &mut tag_buf,
    ) {
        Ok(out) => out,
        Err(e) => return Err(e.to_string())
    };

    memcpy_safe(ciphertext, &ctext_out);
    memcpy_safe(tag, &tag_buf);

    return Ok(0);
}

fn decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8], tag: &[u8], plaintext: &mut [u8]) -> Result<i8, String> {

    let ptext_out = match decrypt_aead(
        Cipher::aes_256_gcm(),
        &key,
        Some(&iv), 
        &[3u8;1],
        &ciphertext,
        &tag,
    ) {
        Ok(out) => out,
        Err(e) => return Err(e.to_string())
    };

    memcpy_safe(plaintext, &ptext_out);

    return Ok(0);

}

// generates aes key from string password, using argon2 hash of password
pub fn get_argon2_hash(to_hash: &[u8], out: &mut [u8]) -> Result<i8,String> {
    let argon2 = Argon2::default();

    match argon2.hash_password_into(to_hash, &[3;16], out) {
        Ok(_) => return Ok(0),
        Err(e) => return Err(e.to_string())
    };

    return Ok(0);

}

pub fn encrypt_data(password: &String, data: &[u8]) -> Result<Vec<u8>, String> {
    let mut aes_key = [0u8;32];
    let mut iv = [0u8; 16];

    match get_argon2_hash(password.as_bytes(), &mut aes_key){
        Ok(_) => {}, 
        Err(e) => return Err(format!("failed in get_argon2_hash: {}", e))
    };

    let mut ctext_buf = Vec::new();
    ctext_buf.extend_from_slice(data);
    let mut tag_buf = [0u8; 16];

    match encrypt(&aes_key, &mut iv, &data, &mut ctext_buf, &mut tag_buf) {
        Ok(_) => {}, 
        Err(e) => return Err(format!("failed in encrypt: {}", e))
    };

    // return a vector that contains the iv, then the tag, and then the ctext
    let mut final_encrypted_data = Vec::new();
    final_encrypted_data.extend_from_slice(&iv);
    final_encrypted_data.extend_from_slice(&tag_buf);
    final_encrypted_data.extend_from_slice(&ctext_buf); 


    return Ok(final_encrypted_data);

}

pub fn decrypt_data(password: &String, data: &[u8]) -> Result<Vec<u8>, String> {
    let mut aes_key = [0u8;32];

    match get_argon2_hash(password.as_bytes(), &mut aes_key){
        Ok(_) => {},
        Err(e) => return Err(format!("failed in get_argon2_hash: {}", e))
    };

    let mut iv = [0u8; 16];
    let mut tag_buf = [0u8;16];
    memcpy_safe_from_src_range(&mut iv, data, 0, 16);
    memcpy_safe_from_src_range(&mut tag_buf, data, 16, 32);


    let mut ptext_buf = Vec::new();
    ptext_buf.extend_from_slice(data);    
    ptext_buf.drain(0..32);

    let mut ctext_buf = Vec::new();
    ctext_buf.extend_from_slice(&ptext_buf);

    match decrypt(&aes_key, &iv, &ctext_buf, &tag_buf, &mut ptext_buf) {
        Ok(_) => {}, 
        Err(e) => return Err(format!("failed in decrypt: {}", e))
    };

    return Ok(ptext_buf);
}

