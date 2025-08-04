# rkd

A minimal key derivation tool built for learning and to explore Rust's crypto crates.

## Supported Algorithms

- Password-Based Key Derivation Function 2 (PBKDF)
- Argon2i
- Argon2id
- Scrypt

## Usage

### Commands

```sh
Usage: rkd <COMMAND>

Commands:
  derive
  verify
  help    Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

#### Derive

The `derive` command allows a user to derive a key using the desired key derivation
function. `rkd` outputs the calculated key and associated salt.

```sh
Usage: rkd derive [OPTIONS] --password <PASSWORD>

Options:
  -p, --password <PASSWORD>      Password
  -m, --method <METHOD>          Desired algorithm: PBKDF2, Argon2 [default: pbkdf2] [possible values: pbkdf2, argon2i, argon2id, scrypt]
  -i, --iterations <ITERATIONS>  Number of iterations
      --length <LENGTH>          Key length in bits [default: 256]
      --memory <MEMORY>          Memory cost in KB (Argon2/scrypt)
      --parallel <PARALLEL>      Parallelism factor (Argon2/scrypt)
  -f, --format <FORMAT>          Output format [default: hex] [possible values: hex, base64]
  -h, --help                     Print help

```

##### Derive Example

```sh
rkd derive -p [password] -m argon2id
```

#### Verify

Th `verify` command will take a salt and hash from the user, recalculate the
hash from user-provided options and compare to the user-provided hash.

```sh
Usage: rkd verify [OPTIONS] --password <PASSWORD> --hash <HASH> --salt <SALT>

Options:
  -p, --password <PASSWORD>      Password to verify
      --hash <HASH>              Hash (hex or base64)
      --salt <SALT>              Salt (hex or base64)
  -m, --method <METHOD>          KDF algorithm [default: pbkdf2] [possible values: pbkdf2, argon2i, argon2id, scrypt]
  -i, --iterations <ITERATIONS>  Parameters used (if different from defaults)
      --memory <MEMORY>
      --length <LENGTH>          [default: 256]
      --parallel <PARALLEL>
  -f, --format <FORMAT>          Input format [default: hex] [possible values: hex, base64]
  -h, --help                     Print help
```

##### Verify Example

```sh
rkd verify -p testpass -m argon2id --salt [salt] --hash [hash]
```
