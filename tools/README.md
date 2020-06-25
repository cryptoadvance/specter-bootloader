# Bootloader Tools

## Install

These tools are developed and tested in isolated Python environment. To create an empty environment using virtualenv run (from the root project directoty):

```bash
virtualenv .venv
```

Python dependencies can installed with hash checking by running:

```
pip install --require-hashes -r requirements.txt
```

## Test key generation

To generate a test key for signing upgrade file use:

```bash
openssl ecparam -name secp256k1 -genkey -noout -out mykey.pem
```

To encrypt a newly generated private key use:

```bash
openssl ec -aes256 -in mykey.pem -out mykey_enc.pem
```

Or, better, use a single command to avoid writing plaintext key to disk:

```bash
openssl ecparam -name secp256k1 -genkey | openssl ec -aes256 -out mykey.pem
```

To inspect generated key use:

```bash
openssl pkey -in mykey.pem -text

```

## Upgrade file generator

Use:

```bash
upgrade-generator.py [--version] [--bootloader <file.hex>] [--firmware <file.hex>] [--sign <keyfile.pem> [--passphrase <"passphrase"> | --ask-passphrase]] <upgrade_file.ext>
```


