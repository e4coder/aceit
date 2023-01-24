use base64::{engine::general_purpose, Engine as _};
use crypto::aes::{self, KeySize};
use crypto::digest::Digest;
use crypto::md5::Md5;
use crypto::sha2::Sha256;
use crypto::symmetriccipher::SynchronousStreamCipher;
use std::iter::repeat;
use std::str::from_utf8;
use std::{collections::HashMap, collections::VecDeque, env};

const FLAGS: &'static [&str] = &["--text", "--key"];
const COMMANDS: &'static [&str] = &["encrypt", "decrypt", "send", "read"];

struct KeyAndIv {
    key: Vec<u8>,
    iv: Vec<u8>,
}

fn generate_key_and_iv(key: &str, iv: &str) -> KeyAndIv {
    let mut sha = Sha256::new();
    sha.input(key.as_bytes());
    let mut key: Vec<u8> = repeat(0u8).take(32).collect();
    sha.result(&mut key);

    let mut md5 = Md5::new();
    md5.input_str(&iv);
    let mut iv: Vec<u8> = repeat(0u8).take(16).collect();
    md5.result(&mut iv);

    KeyAndIv { key: key, iv: iv }
}

fn parse_flags<'a>(args: &'a VecDeque<String>, command_map: &mut HashMap<&'a str, String>) {
    for arg in args {
        let i = arg.find("=").unwrap();
        let mut splitted_arg: Vec<&str> = vec![];
        splitted_arg.insert(0, &arg[0..i]);
        splitted_arg.insert(1, &arg[i + 1..]);
        if splitted_arg.len() == 2 {
            command_map.insert(splitted_arg[0], splitted_arg[1].to_string());
        } else {
            println!("Invaid key value pair: {}", arg);
        }
    }
}

fn process_aes_256_ctr(key: Vec<u8>, iv: Vec<u8>, text: &[u8]) -> Vec<u8> {
    let mut cipher = aes::ctr(KeySize::KeySize256, &key, &iv);
    let mut output: Vec<u8> = repeat(0u8).take(text.len()).collect();
    cipher.process(text, &mut output[..]);
    output
}

fn main() {
    let mut commands_map: HashMap<&str, String> = HashMap::new();
    let mut args: VecDeque<String> = env::args().collect();
    let _ = args.pop_front().unwrap();
    let command = args.pop_front().unwrap();
    parse_flags(&args, &mut commands_map);
    let text = commands_map.get(&FLAGS[0]).unwrap();
    let key_iv_pair = commands_map.get(&FLAGS[1]).unwrap();
    if key_iv_pair.len() < 4 {
        panic!("Key should be atleast 4 charcters long");
    }
    let key = &key_iv_pair[0..key_iv_pair.len() / 2];
    let iv = &key_iv_pair[(key_iv_pair.len() / 2)..];
    let generated_key: KeyAndIv = generate_key_and_iv(key, iv);

    if command == COMMANDS[0] {
        // encrypt
        let cipher_bytes = process_aes_256_ctr(generated_key.key, generated_key.iv, text.as_bytes());
        let cipher_text = general_purpose::STANDARD.encode(&cipher_bytes);
        println!("{}", cipher_text);
    } else if command == COMMANDS[1] {
        // decrypt
        let cipher_text = general_purpose::STANDARD.decode(text).expect("Invalid cipher text!");
        let plaintext_bytes = process_aes_256_ctr(generated_key.key, generated_key.iv, &cipher_text);
        let plaintext = from_utf8(&plaintext_bytes).expect("Invalid utf8");
        println!("{}", plaintext);
    } else {
        println!("Ivalid Command! {}", command);
    }
}
