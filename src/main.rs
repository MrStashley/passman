pub mod crypto_utils;

use std::collections::HashMap;
use byteorder::{ByteOrder, NativeEndian, WriteBytesExt, ReadBytesExt};

pub fn serialize_hashmap(data: &HashMap<Vec<u8>, Vec<u8>>) -> Result<Vec<u8>, String> {
    let mut serialized_data = Vec::new();
    for (hash, password_data) in data {
        serialized_data.extend_from_slice(&hash);
        let password_data_length: u64 = password_data.len().try_into().unwrap();
        println!("password data len: {}", password_data_length);
        serialized_data.write_u64::<NativeEndian>(password_data_length).unwrap(); // TODO add error handling
        serialized_data.extend_from_slice(&password_data);
    }

    return Ok(serialized_data);
}

pub fn deserialize_hashmap(data: &Vec<u8>) -> Result<HashMap<Vec<u8>,Vec<u8>>, String> {
    let data_len:u64 = data.len().try_into().unwrap();
    let mut cur_index:u64 = 0;

    let mut deserialized_data = HashMap::new();

    // TODO add error handling
    while(cur_index < data_len-1) {
        let mut cur_hash = vec![0u8;32];
        crypto_utils::memcpy_safe_from_src_range(&mut cur_hash, data, cur_index.try_into().unwrap(), (cur_index+32).try_into().unwrap());
        cur_index += 32;
        let mut cur_num_vec = vec![0u8; 8];
        crypto_utils::memcpy_safe_from_src_range(&mut cur_num_vec, data, cur_index.try_into().unwrap(), (cur_index+8).try_into().unwrap());
        crypto_utils::hexdump(&cur_num_vec);
        let password_data_len: u64 = NativeEndian::read_u64(&cur_num_vec);
        println!("password data len: {}", password_data_len);
        cur_index += 8;

        let mut cur_password_data = vec![0u8;password_data_len.try_into().unwrap()];

        crypto_utils::memcpy_safe_from_src_range(&mut cur_password_data, data, cur_index.try_into().unwrap(), (cur_index+password_data_len).try_into().unwrap());
        cur_index += password_data_len;

        deserialized_data.insert(
            cur_hash,
            cur_password_data
        );

    }

    return Ok(deserialized_data);
}

pub fn serialize_password_hashmap(data: &HashMap<Vec<u8>, Vec<u8>>) -> Result<Vec<u8>, String> {
    let mut serialized_data = Vec::new();
    for (name, password_data) in data {
        println!("name: ");
        crypto_utils::chardump(name);
        let name_length: u64 = name.len().try_into().unwrap();
        serialized_data.write_u64::<NativeEndian>(name_length).unwrap(); // TODO add error handling
        serialized_data.extend_from_slice(&name);
        println!("name len: {}", name_length);
        crypto_utils::hexdump(&name);
        crypto_utils::hexdump(&serialized_data);

        let password_data_length: u64 = password_data.len().try_into().unwrap();
        println!("password data len: {}", password_data_length);
        serialized_data.write_u64::<NativeEndian>(password_data_length).unwrap(); // TODO add error handling
        serialized_data.extend_from_slice(&password_data);
    }

    crypto_utils::chardump(&serialized_data);
    return Ok(serialized_data);
}

pub fn deserialize_password_hashmap(data: &Vec<u8>) -> Result<HashMap<Vec<u8>,Vec<u8>>, String> {
    let data_len:u64 = data.len().try_into().unwrap();
    let mut cur_index:u64 = 0;

    let mut deserialized_data = HashMap::new();

    // TODO add error handling
    while(cur_index < data_len-1) {
        let mut cur_name_vec = vec![0u8; 8];
        crypto_utils::memcpy_safe_from_src_range(&mut cur_name_vec, data, cur_index.try_into().unwrap(), (cur_index+8).try_into().unwrap());
        crypto_utils::hexdump(&cur_name_vec);
        let name_len: u64 = NativeEndian::read_u64(&cur_name_vec);
        cur_index += 8;

        let mut cur_name = vec![0u8;name_len.try_into().unwrap()];

        crypto_utils::memcpy_safe_from_src_range(&mut cur_name, data, cur_index.try_into().unwrap(), (cur_index+name_len).try_into().unwrap());
        cur_index += name_len;

        let mut cur_num_vec = vec![0u8; 8];
        crypto_utils::memcpy_safe_from_src_range(&mut cur_num_vec, data, cur_index.try_into().unwrap(), (cur_index+8).try_into().unwrap());
        crypto_utils::hexdump(&cur_num_vec);
        let password_data_len: u64 = NativeEndian::read_u64(&cur_num_vec);
        println!("password data len: {}", password_data_len);
        cur_index += 8;

        let mut cur_password_data = vec![0u8;password_data_len.try_into().unwrap()];

        crypto_utils::memcpy_safe_from_src_range(&mut cur_password_data, data, cur_index.try_into().unwrap(), (cur_index+password_data_len).try_into().unwrap());
        cur_index += password_data_len;

        deserialized_data.insert(
            cur_name,
            cur_password_data
        );

    }

    return Ok(deserialized_data);
}


fn main() {
    let password = String::from("password");
    let name = String::from("amazon");
    let mut name_hash = vec![0u8; 32];
    crypto_utils::get_argon2_hash(name.as_bytes(), &mut name_hash).unwrap();
    crypto_utils::hexdump(&name_hash);
    println!();

    let data = String::from("test test test");
    let encrypted_data = crypto_utils::encrypt_data(&password, data.as_bytes()).unwrap();
    crypto_utils::hexdump(&encrypted_data);
    println!();

    let mut test_hash_map = HashMap::new();
    test_hash_map.insert(
        name_hash,
        encrypted_data,
    );

    let name_2 = String::from("google");
    let mut name_hash_2 = vec![0u8; 32];
    crypto_utils::get_argon2_hash(name_2.as_bytes(), &mut name_hash_2).unwrap();
    crypto_utils::hexdump(&name_hash_2);
    println!();

    let mut password_data_hashmap_2 = HashMap::new(); 
    let field_1 = String::from("name");
    let value_1 = String::from("google");
    let field_2 = String::from("username");
    let value_2 = String::from("cole");
    let field_3 = String::from("password");
    let value_3 = String::from("password");

    password_data_hashmap_2.insert(
        field_1.as_bytes().to_vec(),
        value_1.as_bytes().to_vec()
    );
    password_data_hashmap_2.insert(
        field_2.as_bytes().to_vec(),
        value_2.as_bytes().to_vec()
    );
    password_data_hashmap_2.insert(
        field_3.as_bytes().to_vec(),
        value_3.as_bytes().to_vec()
    );

    let data_2 = serialize_password_hashmap(&password_data_hashmap_2).unwrap();
    let encrypted_data_2 = crypto_utils::encrypt_data(&password, &data_2).unwrap();
    crypto_utils::hexdump(&encrypted_data_2);
    println!();

    test_hash_map.insert(
        name_hash_2,
        encrypted_data_2,
    );

    let serialized_test = serialize_hashmap(&test_hash_map).unwrap();

    println!("Serialized data");
    crypto_utils::hexdump(&serialized_test);
    println!("End serialized data");

    let deserialize_test = deserialize_hashmap(&serialized_test).unwrap();

    println!("deserialzed hashmap: ");
    for (hash, data) in &deserialize_test {
        let decrypted_password_data = crypto_utils::decrypt_data(&password, &data).unwrap();
        let deserialized_password_data = deserialize_password_hashmap(&decrypted_password_data).unwrap();
        for (password_data_name, password_data) in &deserialized_password_data {
            println!("name: ");
            crypto_utils::chardump(&password_data_name);
            println!("data: ");
            crypto_utils::chardump(&password_data);
        }

        break;

    }
    
}

