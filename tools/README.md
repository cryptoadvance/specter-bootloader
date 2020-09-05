# Bootloader Tools

- [Bootloader Tools](#bootloader-tools)
  - [Install](#install)
  - [Test key generation](#test-key-generation)
  - [Upgrade file generator](#upgrade-file-generator)
    - [**gen** command](#gen-command)
    - [**sign** command](#sign-command)
    - [**dump** command](#dump-command)
  - [Creation of initial firmware](#creation-of-initial-firmware)

## Install

These tools are developed and tested in isolated Python environment. To create an empty environment using virtualenv run (from the root project directoty):

```bash
virtualenv .venv
```

Python dependencies can installed with hash checking by running:

```bash
pip install --require-hashes -r requirements.txt
```

To update requirements.txt with hash generation use:

```bash
pip freeze > requirements.in
pip-compile requirements.in --generate-hashes --allow-unsafe
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

To generate and sign an upgrade file use the provided tool: `upgrade-generator.py`. It creates a signed container with binary images of the Bootloader or of the Main Firmware or both.

Contents of a produced upgrade file determine which keys are authorized to sign this upgrade. If an upgrade file contains the Bootloader, only the Vendor keys can be used to sign it. If only the Main Firmware is contained inside an upgrade file, it can be signed with either Vendor keys or Maintainer keys or any mix of both.

Upgrade generator supports three commands:

- [**gen**](#gen-command) - generate an upgrade file, with optional signing
- [**sign**](#sign-command) - add a signature to an existing upgrade file
- [**dump**](#dump-command) - displays contents of an upgrade file

To get full usage instructions run `upgrade-generator.py <command> --help`.

### **gen** command

```console
$ upgrade-generator.py gen --help
Usage: upgrade-generator.py gen [OPTIONS] <upgrade_file.bin>

  This command generates an upgrade file from given firmware files in Intel
  HEX format. It is required to specify at least one firmware file: Firmware
  or Bootloader.

  In addition, if a private key is provided it is used to sign produced
  upgrade file. Private key should be in PEM container with or without
  encryption.

Options:
  -b, --bootloader <file.hex>   Intel HEX file containing the Bootloader.
  -f, --firmware <file.hex>     Intel HEX file containing the Main Firmware.
  -k, --private-key <file.pem>  Private key in PEM container.
  -p, --platform <platform>     Platform identifier, i.e. stm32f469disco.
  --help                        Show this message and exit.
```

### **sign** command

```console
$ upgrade-generator.py sign --help
Usage: upgrade-generator.py sign [OPTIONS] <upgrade_file.bin>

  This command adds a signature to an existing upgrade file. Private key
  should be provided in PEM container with or without encryption.

  The signature is checked for duplication, and any duplicating signatures
  are removed automatically.

Options:
  -k, --private-key <filename.pem>
                                  Private key in PEM container used to sign
                                  produced upgrade file.  [required]

  --help                          Show this message and exit.
```

### **dump** command

```console
$ upgrade-generator.py dump --help
Usage: upgrade-generator.py dump [OPTIONS] <upgrade_file.bin>

  This command dumps information regarding firmware sections and lists
  signatures with public key fingerprints.

Options:
  --help  Show this message and exit.
```

## Creation of initial firmware

To program a "clean" device a complete firmware image needs to be created, including at least the Start-up code and one copy of the Bootloader. The Main Firmware can be added-up as well to make the device fully operating right after programming.

> IMPORTANT: Initial firmware is not intended for distribution as it does not use signature verification!

The recommended way to create an initial firmware is by the help of `make-initial-firmware.py` tool. Usage instructions can be obtained by running it with `-help` option:

```console
$ make-initial-firmware.py --help
Usage: make-initial-firmware.py [OPTIONS] <output_file_name>

  This command makes a firmare file for initial programming of a "clean"
  defice. The firmware file is made by combining together the Start-up code,
  the Bootloader, and, optionally, the Main Firmware.

Options:
  -s, --startup <file.hex>     Intel HEX file containing the Start-up code.
                               [required]

  -b, --bootloader <file.hex>  Intel HEX file containing the Bootloader.
                               [required]

  -f, --firmware <file.hex>    Intel HEX file containing the Main Firmware.
  -bin, --bin-output           Outputs firmware in raw binary format.
  --help                       Show this message and exit.
```
