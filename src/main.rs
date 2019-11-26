extern crate clap;
extern crate rand;
extern crate rsa;
extern crate serde_json;

use clap::{App, SubCommand};
use rand::rngs::OsRng;
use rsa::{hash::Hashes, PaddingScheme, PublicKey, RSAPrivateKey, RSAPublicKey, BigUint};
use rsa_der::{public_key_from_der, public_key_to_der};
use std::{io, io::prelude::*};

fn generate_key() {
    let mut rng = OsRng::new().expect("no secure randomness available");
    let mut cin = String::new();
    println!("请输入密钥位数(推荐使用2048位 注意: n位的密钥只能加密n位的数据,密钥位越少,被破解的可能越大):");
    io::stdin()
        .read_line(&mut cin)
        .expect("Failed to read bits");
    let bits: usize = cin.trim().parse().expect("Please type a number!");
    println!("正在生成{}位密钥...", bits);
    let key = RSAPrivateKey::new(&mut rng, bits).expect("failed to generate a key");

    let serialized = serde_json::to_string(&key).unwrap();

    loop {
        println!("将私钥保存到:");
        cin.clear();
        io::stdin().read_line(&mut cin).expect("请输入一个有效地址");
        let mut file: std::fs::File;
        match std::fs::File::create(&cin.trim()) {
            Err(error) => {
                println!("{} 不是一个有效地址", cin);
                println!("error: {} 请输入一个有效地址", error);
            }
            Ok(f) => {
                file = f;
                file.write_all(serialized.as_bytes()).unwrap();
                break;
            }
        };
    }

    let der_publickey = public_key_to_der(&key.n().to_bytes_be(), &key.e().to_bytes_be());
    let publickeybase64 = base64::encode(&der_publickey);

    println!("公钥为: {}", publickeybase64);
}

fn signature() -> String {
    loop {
        println!("请输入私钥位置:");
        let mut cin = String::new();
        io::stdin()
            .read_line(&mut cin)
            .expect("Failed to read bits");
        let file = match std::fs::File::open(&cin.trim()) {
            Ok(f) => f,
            Err(error) => {
                println!("{} 不是一个有效地址", cin);
                println!("error: {} 请输入一个有效地址", error);
                continue;
            }
        };

        let private_key: RSAPrivateKey = match serde_json::from_reader(&file) {
            Err(error) => {
                println!("{} 不是一个有效的私钥", cin);
                println!("error: {}", error);
                continue;
            }
            Ok(key) => key,
        };

        cin.clear();
        println!("请输入需要签名的信息:");
        io::stdin()
            .read_line(&mut cin)
            .expect("Failed to read bits");
        
        let msg = &cin.trim().as_bytes();

        let sig = private_key
            .sign::<Hashes>(PaddingScheme::PKCS1v15, None, msg)
            .expect("error");
        
        return base64::encode(&sig);
    }
}

fn verify() -> bool {
    loop {
        println!("请输入公钥:");
        let mut cin = String::new();
        io::stdin()
            .read_line(&mut cin)
            .expect("Failed to read bits");
        let (n, e) = match public_key_from_der(&base64::decode(&cin.trim()).unwrap()) {
            Err(error) => {
                println!("这不是一个合法的公钥:");
                println!("error {}", error);
                continue;
            }, 
            Ok(key) => {
                key
            },
        };

        let public_key = RSAPublicKey::new(BigUint::from_bytes_be(&n), BigUint::from_bytes_be(&e)).unwrap();

        println!("请输入签名信息:");
        cin.clear();
        io::stdin()
            .read_line(&mut cin)
            .expect("Failed to read bits");
        let msg_sig = base64::decode(&cin.trim()).unwrap();

        
        println!("请输入原信息:");
        cin.clear();
        io::stdin()
            .read_line(&mut cin)
            .expect("Failed to read bits");
        let msg = cin.trim().as_bytes();

    
        match public_key.verify::<Hashes>(PaddingScheme::PKCS1v15, None, &msg, &msg_sig) {
            Ok(()) => { return true; }
            Err(err) => { 
                println!("error: {}", err);
                return false; 
            }  
        }
    }
}

fn main() {
    let matches = App::new("signature")
        .version("0.1")
        .author("readlnh")
        .about("digital signature")
        .subcommand(SubCommand::with_name("key").about("generate key pairs"))
        .subcommand(SubCommand::with_name("signature").about("sign with the private key"))
        .subcommand(SubCommand::with_name("verify").about("verify with the public key"))
        .get_matches();

    if let Some(_matches) = matches.subcommand_matches("key") {
        generate_key();
    }
    if let Some(_matches) = matches.subcommand_matches("signature") {
        let signature_msg = signature();
        println!("签名信息: {}", signature_msg);
    }
    if let Some(_matches) = matches.subcommand_matches("verify") {
        if verify() {
            println!("验证通过");
        }
        else {
            println!("验证失败");
        }
    }

    // Encrypt
    /*let data = b"hello world";
    let enc_data = key.encrypt(&mut rng, PaddingScheme::PKCS1v15, &data[..]).expect("failed to encrypt");
    //println!("{:?}", &enc_data);
    //assert_ne!(&data[..], &enc_data[..]);

    // Decrypt
    let dec_data = key.decrypt(PaddingScheme::PKCS1v15, &enc_data).expect("failed to decrypt");
    println!("{:?}", str::from_utf8(&dec_data));

    let msg = b"Thu Dec 19 18:06:16 EST 2013\n";
    let xx = base64::encode(&msg);
    println!("{}", xx);



    //println!("{:?}", str::from_utf8(&expected_sig));

    //publickey.verify().expect("wwwwwww");

    //assert_eq!(&data[..], &dec_data[..]);*/
}
