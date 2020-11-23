# Using your own firmware and bootloader

## Building custom bootloader with your keys

If you want to replace the bootloader public keys and sign the firmware upgrades yourself
you need to create a `keys/selfsigned/pubkey.c` file and define there your public keys in uncompressed form.

You also can specify the number of signatures required for firmware and bootloader verification.

Look at [`keys/test/pubkeys.c`](../keys/test/pubkeys.c) as an example - it contains a bunch of keys derived from pem files, electrum seed and bip39 seed.

When you have the `pubkeys.c` file you can build the startup code and bootloader by running from the root directory of the bootloader repo:

```sh
make stm32f469disco
```

Read the [main readme](../README.md) to learn more, pay extra attention to the `READ_PROTECTION` and `WRITE_PROTECTION` parameters.

We recommend to make a bootloader without any protection at first, flash it, sign and flash the firmware, check that everything works, and then bump the version of the bootloader, recompile with `READ_PROTECTION=1` and `WRITE_PROTECTION=1`, sign and upload the bootloader upgrade.

## Creating initial firmware

When `make` is done the `.hex` files will be created in the `build` folder. To get the initial firmware that you can flash to the empty discovery board you need to use a tool `make-initial-firmware.py` in the [`tools`](../tools) folder.

To create initial firmware go to the `tools` folder and install the dependencies:

```sh
cd tools
virtualenv .venv
pip install -r requirements.txt
```

Now you can create initial firmware:

```sh
python3 make-initial-firmware.py -s ../build/stm32f469disco/startup/release/startup.hex -b ../build/stm32f469disco/bootloader/release/bootloader.hex -bin initial_firmware.bin
```

The resulting `initial_firmware.bin` can be copy-pasted to the `DIS_F469I` volume that appears when you connect the board with miniUSB.

Alternatively, if you have [`stlink-tools`](https://github.com/stlink-org/stlink) installed, you can flash the firmware with verification using:
```sh
st-flash write initial_firmware.bin 0x8000000
```

After flashing of this initial firmware you should see an error screen of the bootloader that "No valid firmware found" - this is what we expect because we didn't upload firmware yet. For that we can generate an upgrade file.

## Creating upgrade files

First, compile firmware of Specter-DIY with `USE_DBOOT=1` flag. It will create a `bin/specter-diy.hex` file:

```sh
make clean
make disco USE_DBOOT=1
```

Now you come back to the `tools` directory and generate the upgrade file:

```sh
python3 upgrade-generator.py gen -f ../../bin/specter-diy.hex -p stm32f469disco specter_upgrade.bin
```

Now we got the `specter_upgrade.bin` that we need to sign. If your keys are stored on the hardware wallet you need to sign a bitcoin message - most hardware and software wallets can do that.

Use this command to get the message to sign:

```sh
python3 upgrade-generator.py message specter_upgrade.bin 
```

It will return something like `1.4.0rc3-1sujn22lsgatcpyesj9v8lf4zts6myds0cwdl9ukk7pqnasr06laq2gm2yt` - here you see that it's a firmware version 1.4.0-rc3 and bech32-encoded hash of the firmware. You can sign this message now and when you get a signature in base64 format you need to add it to the upgrade:

```sh
python3 upgrade-generator.py import-sig -s IP6SuI23iNNxYLCyh/J3FsY8Zd687tfMNFR37ZppprGNDG1Ij3Oh4u3PvrYmdno/PRG9Lqourael5oAJ+kWT+d4= specter_upgrade.bin
```

Repeat it for necessary number of signatures, now you should be able to copy this signed `specter_upgrade.bin` file to the SD card and load the firmware to the device.

Verify that upgrade process works, firmware is fine etc. After that you can upgrade the bootloader to "protected" one.

## Protected bootloader

First we need to bump the bootloader version, because only upgrades are possible. For that edit the content of the `<version:tag10>version-info-here</version:tag10>` tag in `platforms/stm32f469disco/bootloader/main.c` file.

Now clean the build and rebuild with protections enabled:

```sh
make clean
make stm32f469disco READ_PROTECTION=1 WRITE_PROTECTION=1
cd tools
python3 upgrade-generator.py gen -p stm32f469disco -b ../build/stm32f469disco/bootloader/release/bootloader.hex specter_upgrade_bootloader.bin
```

And then just like last time, get the message, import signatures and upgrade the bootloader with SD card.

Now you have a fully protected hardware wallet with secure bootloader and verification of the firmware.

Be safe, stack sats.
