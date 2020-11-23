# Specter Bootloader

This is a secure bootloader for [Specter hardware wallet](https://github.com/cryptoadvance/specter-diy). It allows upgrading of the MicroPython virtual machine, frozen Python code, and the Bootloader itself via microSD card. Distributed firmware is signed using the ECDSA algorithm with secp256k1 ("Bitcoin") curve, and multiple signature schemes are supported.

## How it works

The Bootloader resides in the internal flash memory of the microcontroller and consists of two parts:

- 1-st stage non-upgradable bootloader called the [Start-up code](#Start-up-code)
- 2-nd stage bootloader called simply the [Bootloader](#Bootloader)

### Start-up code

First, at power-on, the **Start-up code** takes control over the microcontroller. Its role is quite simple: to verify the integrity of up to 2 copies of the Bootloader and select the one with the latest version to be executed next.

### Bootloader

The Bootloader implements all the steps of the firmware upgrade process:

- Scans removable media for upgrade files
- Ensures that the upgrade file is valid, not corrupted, and built for the right platform
- Checks that this file contains a later version of the firmware than current
- Copies payload from an upgrade file to internal flash memory
- Verifies the signatures and makes the firmware runnable if they are valid

More details are provided in the [Bootloader Specification](/doc/bootloader-spec.md) document.

## Building

A single master Makefile is used to build the Bootloader, and if available, the Start-up code as well. Currently, the following platforms are supported:

- `stm32f469disco` - Specter wallet based on the [STM32F469 Discovery kit](https://www.st.com/en/evaluation-tools/32f469idiscovery.html)
- `testbench` - a "virtual" device simulated on the desktop computer

To build for `stm32f469disco` platform, the `arm-none-eabi-gcc` (GNU Tools for Arm Embedded Processors 9-2019-q4-major) toolchain is used.

For the `testbench` platform, a default GCC/Clang toolchain is used because the binary is intended to run on the host machine.

To build the Bootloader, the desired platform is specified as the first argument in Make's command line. To build debug version, additionally, `DEBUG=1` needs to be specified.

```shell
make <platform_name> [DEBUG=1]
```

For example, to build debug versions of the Bootloader and the Start-up code for the STM32F469 Discovery board use:

```shell
make stm32f469disco DEBUG=1
```

`KEYS=...` parameter is used to define which keys the bootloader will use for verification. Default option is `KEYS=selfsigned` and you need to create the `./keys/selfsigned/pubkeys.c` file with your public keys to make it working. You can also build firmware with `production` or `test` keys. For `test` keys there are known private keys. `production` keys are secret.

Read more about building the bootloader and generating upgrades in [doc/selfsigned.md](doc/selfsigned.md).

## Tests

Along with the `testbench` platform, the project includes a suite of unit tests for the core functions of the Bootloader. These tests are using a convenient single-header [Catch2 framework](https://github.com/catchorg/Catch2). To build and execute unit tests, use:

```shell
make test
```

## Tools

This project includes a set of tools used:

- To generate and sign an upgrade file
- To create a specialized firmware intended for a "clean" device
- To create test vectors used in known answer tests for the cryptographic algorithms which do not have such vectors published "officially."

For more information please see [Tools documentation](/tools/README.md)

## Usage

Use the following steps as an idea of a typical use case:

- Build the Bootloader and the Start-up code [more...](#Building)
- Create an initial firmware using `make-initial-firmware.py` and program it in a "clean" device
- Once a new version of the Bootloader or the Main Firmware is released, use `upgrade-generator.py` to generate an upgrade file
- Sign produced upgrade file with applicable private keys using `upgrade-generator.py` or an air-gapped device
- Copy your upgrade file to a root directory of a microSD card, insert it in the device, and reboot
- To get version information on each power-on, create an empty file named ".show_version" in the card's root directory

For additional information on provided tools please see [Tools documentation](/tools/README.md).

## Read and write protection for flash memory

These features are controlled through the **Make's** command line by adding corresponding variables:

- `READ_PROTECTION=0` - programs RDP Level 0 (has no practical use)
- `READ_PROTECTION=1` - programs RDP Level 1
- `READ_PROTECTION=2` - programs RDP Level 2 (blocked by default, see below)
- `WRITE_PROTECTION=1` - enables write protection for the Start-up code, Main Firmware, and the Bootloader itself

**IMPORTANT:** After changing these variables it is needed to clean the build directory before the next build:

```shell
make clean
```

### Read protection

The **stm32f469disco** platform supports three levels of read protection:

- RDP Level 0 - no protection at all
- RDP Level 1 - no external access to flash memory, JTAG/SWD can be used to erase the chip
- RDP Level 2  - JTAG/SWD is disabled completely, protection settings cannot be changed

For additional information please see the STM32F469xx Reference Manual.

You can change RDP from level 1 to level 0 using `openocd`.
This will erase all the content of the microcontroller:

```
openocd -f openocd.cfg -f ocd-unlock.cfg
```

RDP level 2 is unreversable, so think twice before enabling it.

To enable RDP Level 2 in addition to `READ_PROTECTION=2` it is needed to modify the source code manually as well. In the file `platforms/stm32f469disco/bootloader/bl_syscalls.c`, the block of code in `blsys_flash_read_protect()` function inside `#ifdef 0` should be made active.

**WARNING:** By enabling RDP Level 2 protection mode you are making an irreversible change to the flash memory of the MCU. It is not possible to use the board for debugging after running the Bootloader compiled with `READ_PROTECTION=2`. The Start-up code becomes unreplaceable as well.

### Write protection

When the write protection enabled with `WRITE_PROTECTION=1` the Bootloader applies the write protection to every sector of the flash memory it updates. The sector containing the Start-up code is write-protected as well.

When the Bootloader is about to update a flash memory sector it removes write-protection temporary. This feature works even if `WRITE_PROTECTION` is not enabled. In the latter case write protection is not restored after the update.
