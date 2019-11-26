# RSA Demo for Loongson LS1C030CB
This is a simple demo for loongson

## How to build
Cross-compile on Ubuntu18.04 x86-64

```bash
cargo build --release --target=mipsel-unknown-linux-musl
```

Note: You need to set the linker for cargo yourself.

## How to use
Just use `--help` flag to get the information.

```
signature 0.1
readlnh
digital signature

USAGE:
    signature_rsa [SUBCOMMAND]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    decrypt      decrypt with the private key
    encrypt      encrypt with the public key
    help         Prints this message or the help of the given subcommand(s)
    key          generate key pairs
    signature    sign with the private key
    verify       verify with the public key
```