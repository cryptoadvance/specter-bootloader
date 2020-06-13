# Bootloader Tools

## Test key generation

To generate a test key for signing upgrade file use:

```bash
openssl ecparam -name secp256k1 -genkey -noout -out mykey.pem
```

To inspect generated key:

```bash
openssl pkey -in mykey.pem -text

```

## Upgrade file generator

Use:

```bash
upgrade-generator.py [--version] [--bootloader <file.hex>] [--firmware <file.hex>] [--sign <keyfile.pem> [--passphrase <"passphrase"> | --ask-passphrase]] <upgrade_file.ext>
```


