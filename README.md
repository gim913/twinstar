```
                     __  __         __
   ____  ____  _____/ /_/ /_  _____/ /_____ ______
  / __ \/ __ \/ ___/ __/ __ \/ ___/ __/ __ `/ ___/
 / / / / /_/ / /  / /_/ / / (__  ) /_/ /_/ / /
/_/ /_/\____/_/   \__/_/ /_/____/\__/\__,_/_/
```

- [Documentation](https://docs.rs/northstar)
- [GitHub](https://github.com/panicbit/northstar)

# Usage

Add the latest version of northstar to your `Cargo.toml`.

## Manually

```toml
northstar = "0.4.0" # check crates.io for the latest version
```

## Automatically

```sh
cargo add northstar
```

# Generating a key & certificate

Run
```sh
mkdir cert && cd cert
openssl req -x509 -nodes -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365
```
and enter your domain name (e.g. "localhost" for testing) as Common Name (CN).

Alternatively, if you want to include multiple domains add something like `-addext "subjectAltName = DNS:localhost, DNS:example.org"`.
