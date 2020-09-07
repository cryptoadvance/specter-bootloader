# Specter Bootloader

- [Specter Bootloader](#specter-bootloader)
  - [Feature Summary](#feature-summary)
    - [Multisignature support](#multisignature-support)
  - [Principles of operation](#principles-of-operation)
    - [Bootloader selection procedure](#bootloader-selection-procedure)
    - [Firmware upgrade procedure](#firmware-upgrade-procedure)
    - [Normal boot procedure](#normal-boot-procedure)
  - [Implementation details](#implementation-details)
    - [Version format](#version-format)
    - [Section header format](#section-header-format)
    - [Signature section format](#signature-section-format)
    - [Firmware conversion from an Intel HEX file](#firmware-conversion-from-an-intel-hex-file)
    - [Embedded version tag](#embedded-version-tag)
    - [Embedded memory map](#embedded-memory-map)
    - [Integrity check record format](#integrity-check-record-format)
  - [Internal Flash memory map](#internal-flash-memory-map)

## Feature Summary

*   Source of firmware: SD/MicroSD card
*   File systems: FAT32
*   Access method: read-only
*   Integrity check: CRC32
*   Digital signature: ECDSA, secp256k1, SHA-256
*   Versioning: semantic versioning in a 32-bit number
*   Bootloader upgrade: two copies of bootloader and non-upgradable start-up code
*   Downgrade: prohibited for the Bootloader and the Main Firmware
*   Firmware file contains the following sections:
    *   One or several payload sections, including “internal” and “boot”
    *   Signature section “sign”
*   Each section of the firmware file has its own header and is protected by a separate CRC code
*   The digital signature is calculated over all payload sections
*   Key hierarchy:
    *   Vendor keys capable to sign Bootloader and/or Main Firmware
    *   Maintainer keys capable to sign MainFirmware only
*   Key management: Bootloader stores a set of Vendor public keys and a set of Maintainer public keys
*   New keys are added and compromised keys are revoked by issuing a new Bootloader
*   Multisignature support with configurable thresholds

### Multisignature support

The Bootloader stores minimum signature thresholds for the Bootloader and for the Main Firmware. The payload is considered valid only if it has a number of valid signatures not less than the corresponding threshold. The Main Firmware may have a mixed set of signatures produced by Vendor and Maintainer keys. All signatures of the Bootloader must be produced using Vendor keys only.

In case an upgrade file contains both the Bootloader and the Main Firmware it must be signed following the same rules as for the Bootloader alone.

## Principles of operation

### Bootloader selection procedure

These steps are performed by the Start-up code, non-upgradable part of Bootloader that is executed straight on device reset.

1. Read Bootloader’s integrity check records stored at the end of 2 pre-determined sectors, containing copies of Bootloader.
2. Select a copy of the Bootloader that meets the following criteria:
    1. Its integrity check record exists and is correct (checking record’s own CRC).
    2. Its contents (executable code and data) also passes the integrity check.
    3. Its version is the latest in case two correct Bootloader copies exist. If both copies are correct and have identical versions the first copy is selected.
3. If no Bootloader copy is selected, the Start-up code enters an endless loop with a specific LED indication.
4. Remap interrupt vectors and branch to the entry point of selected Bootloader (its reset vector).

### Firmware upgrade procedure

In case any of the steps 1-5 fails, the Bootloader unmounts the SD card and proceeds with a normal boot described under “Normal boot procedure”. In other cases, the microcontroller is rebooted, unmounting the SD card beforehand.

1. Ensure that the SD card is inserted.
2. Mount the file system.
3. Find a firmware file having a predetermined name format and extension, like “specter_upgrade_v1.05.01.bin” using a pattern “specter_upgrade*.bin” in the root directory of SD card. Presence of more than one matching files aborts upgrade process.
4. Read fixed-size headers of all sections from the firmware file into RAM, check their CRC. The presence of any unknown section aborts the firmware upgrade process.
5. Obtain and verify version information from the headers, including:
    1. Version of Firmware, check if it is later than currently programmed
    2. Version of Bootloader if “boot” section exists, check if it is later than programmed
6. Verify the correctness of all parameters from headers and that the firmware is compatible with the platform on which the Bootloader is running.
7. Verify that the last section is the “sign” section. Parse its contents extracting fingerprint-signature pairs, creating a table in RAM. Ensure that:
    3. A public key with a provided fingerprint exists in the pre-defined table stored within the Bootloader. Otherwise, remove the signature from the RAM table.
    4. The key referenced by the fingerprint is capable to sign the given payload. Otherwise, remove the signature from the RAM table. The use of Maintainer keys is not allowed to sign a firmware file containing the “boot” section.
    5. The key referenced by fingerprint was not encountered in the RAM table before. Otherwise, remove the duplicating signature from the RAM table.
    6. The number of remaining signatures is not less than a predefined minimum signature threshold (a separate threshold for the Firmware and for the Bootloader).
8. Verify the integrity of all payload sections using the CRC algorithm.
9. Perform partial erase of internal flash memory as needed to store the new firmware, excluding sectors occupied by the currently executed copy of the Bootloader, the Start-up code, internal file systems and the key storage.
10. Copy payload sections from an upgrade file file to internal flash memory.
11. Perform verification of signature(s) using a prepared signature table in RAM. Verified data includes:
    7. Section headers in RAM (not from SD card)
    8. Payload data as read from non-removable Flash devices (not from SD card)
12. In case the signature verification is successful, the Bootloader creates an integrity check record in Internal Flash memory containing a CRC code of firmware sections along with version. In case the Bootloader is upgraded as well, an integrity check record is created at the end of its sector.
13. Unmount the SD card and reboot.

### Normal boot procedure

1. Ensure that the integrity check record for the Main Firmware exists and not corrupted by verifying its CRC. The absence of this record means that the device is blank or signature verification has failed. In this case, the Bootloader enters an endless loop with a specific LED and LCD indication.
2. Verify the integrity of the Firmware using CRC stored in the integrity check record. In case of failure, erase the integrity check record and reboot.
3. Remap interrupt vectors and branch to the entry point of the Main Firmware (its reset vector).

## Implementation details

### Version format

Semantic versioning is used in the following format MAJOR.MINOR.PATCH[-rcREVISION]. All four components of the version are coded using decimal orders of a 32-bit number, as follows:

* MAJOR: (0 ... 41) x 1e8
* MINOR: (0 ... 999) x 1e5
* PATCH: (0 ... 999) x 1e2
* REVISION: 0 ... 98 - release candidate, 99 - stable version

For example, version “1.22.134-rc5” is coded as 102213405 decimal (0x617a71d). REVISION component is used **only for release candidates**. For the stable versions, revision is always equal to 99 to position them in history “later” than any release candidate and blocking downgrading to non-stable versions. Another example: a stable version “12.0.15” is coded as 1200001599. Maximally supported version is “41.999.999”, which equals to 4199999999 (0xfa56e9ff). Versions above this number are considered invalid. Version constant 0x00000000 is reserved for “undefined” value.

> The Bootloader may have an option allowing only stable versions (REVISION equal to 99) to be flashed into end-user devices.

### Section header format

Each section stored in the firmware file has a fixed size header, as defined in the following C language structure:

```c
// Section header
//
// This structure has a fixed size of 256 bytes. All 32-bit words are stored in
// little-endian format. CRC is calculated over first 252 bytes of this
// structure.
typedef struct {
  uint32_t magic;         // Magic word, BL_SECT_MAGIC (“SECT”, 0x54434553 LE)
  uint32_t struct_rev;    // Revision of structure format
  char name[16];          // Name, zero terminated, unused bytes are 0x00
  uint32_t pl_ver;        // Payload version, 0 if not available
  uint32_t pl_size;       // Payload size
  uint32_t pl_crc;        // Payload CRC
  uint8_t attr_list[216]; // Attributes, list of: { key, size [, value] }
  uint32_t struct_crc;    // CRC of this structure using LE representation
} bl_section_t;
```

Parameter `name` contains a zero-terminated string with a section name, one of “internal”, “boot”, “sign” or probably other variants in the future versions.

Array `attr_list[]` contains a list of required and optional attributes, specific to each type of section.  Each attribute record consists of **key** byte, **size** byte, and optionally **value** field (0...214 bytes) whose length is specified in the size byte. Keys are unique within the attribute list and have the same meaning for each section.

Numerical arguments are coded as variable length integers in little-endian format. For example, a 32-bit number 0x00012345 is coded as three bytes 0x45, 0x23, 0x01. Unused bytes of attr_list[] are filled with 0x00.

String attributes are stored without terminating null characters and are limited in size to 32 characters (per each attribute).

### Signature section format

The signature section has a standard section header with the following specifics:

```c
.name = “sign”
.pl_ver = 0
.attr_list = { bl_attr_algorithm, 16, 's', 'e', 'c', 'p', '2', '5', '6', 'k', '1', '-', 's', 'h', 'a', '2', '5', '6', ... }
```

Section name “sign” is used to identify the signature section. Only one signature section is allowed and it must be the last section in an upgrade file.

Attribute array must contain at least one required attribute, `bl_attr_algorithm` specifying digital signature algorithm as a string. Currently, only “secp256k1-sha256” is supported.

The contents of the signature section is a list of fingerprint-signature pairs. When “secp256k1-sha256” is specified, the fingerprint is 16 first bytes of SHA-256 hash of the uncompressed public key (65 bytes, beginning with 0x04), and the signature is a 64-byte compact signature:

```text
  0x00000000  [16]: SHA-256(pubkey1), [64]: signature1
  0x00000050  [16]: SHA-256(pubkey2), [64]: signature2
  0x000000A0  [16]: SHA-256(pubkey3), [64]: signature3
  0x000000F0  [16]: SHA-256(pubkey4), [64]: signature4
    ...
  (N-1) * 80  [16]: SHA-256(pubkeyN), [64]: signatureN
```

Calculation of digital signature is a multi-step process:

1. A separate SHA-256 hash is calculated over each payload section including its header: \
  **_h<sub>i</sub>_ = SHA-256( _header<sub>i</sub>_ | _payload<sub>i</sub>_ )**
2. Each produced value is concatenated with corresponding section name as 16 byte array and 32-bit version number in little-endian format, forming a 52-byte payload sentence: \
  **_P<sub>i</sub>_ = _name<sub>i</sub>_ | _version<sub>i</sub>_ | _h<sub>i</sub>_**
3. A message to sign is produced by concatenating all payload sentences: \
  **_M_ = _P<sub>0</sub>_ | … | _P<sub>i</sub>_**
4. Message is signed with a private key d using chosen digital signature algorithm: \
  **_signature<sub>i</sub>_ = DSA_SIGN( _d_, _M_ )**

The process is divided in four steps to allow delegation of steps 3-4 to an air-gapped device, like Specter itself. In this scenario only a list of hashes with brief metadata **[_P<sub>0</sub>_, …, _P<sub>n</sub>_]**, is transferred instead of full payload sections and headers. Name and version fields provide additional information for visual confirmation on the screen.

Additional signatures can be added later by re-writing the signature section of an upgrade file. All signatures must be produced using the same algorithm.

### Firmware conversion from an Intel HEX file

All firmware components used to generate payload sections are initially supplied in Intel HEX format. Before placing into payload sections and signing, these files are converted to binary form. During this conversion, file name, starting address, entry point and other metadata are not preserved. All holes in the address space are filled with 0xFF bytes producing a linear binary file with its size equal to the difference between the first and the last address in the source HEX file.

Entry point for the firmware modules intended for ARM Cortex-M4 platform is stored in the second ISR vector, as usual and not needed to be specified explicitly. It is supposed that for other platforms not supporting this feature, entry point will be specified in section’s attribute.

### Embedded version tag

In the source firmware files payload version is defined with an embedded XML-like version tag: **&lt;version:tag10>** followed by exactly 10 decimal digits specifying semantic version as defined in “Version Format” subsection. For example, version “1.22.134-rc5” is defined by:

```xml
<version:tag10>102213405</version:tag10>
```

This tag could be included anywhere within the firmware body. Upgrade generator searches the firmware image for an embedded version tag after conversion from Intel HEX format to linear binary image. If the version tag is not found, the firmware version is considered “undefined”. If the firmware includes more than one version tag (of the same format), the firmware is considered invalid.

### Embedded memory map

To support additional tools like a script composing firmware for initial programming, the Bootloader may include an embedded memory map. This is a data structure containing address and length properties of firmware components specific for the platform for which the Bootloader is built.

The embedded memory map is identified by outside XML-like tag:

```xml
<memory_map:lebin>...</memory_map:lebin>
```

But unlike canonical XML internal contents is a binary structure with numerical values stored in little-endian format. At the moment of writing of this document an embedded memory consists of the listed below values. But more values may be added later without breaking compatibility.

```c
// XML-like memory map record containing elements in LE binary format
typedef struct {
  // Opening tag: "<memory_map:lebin>"
  char opening[18];
  // Size of one element in bytes: 4 for 32-bit platform
  uint8_t elem_size;
  // Size in flash memory reserved for the Bootloader
  uintptr_t bootloader_size;
  // Start of the Main Firmware in flash memory
  uintptr_t main_firmware_start;
  // Size reserved for the Main Firmware
  uintptr_t main_firmware_size;
  // Closing tag: "</memory_map:lebin>"
  char closing[19];
} bl_memmap_rec_t;
```

### Integrity check record format

An integrity check record contains the size and CRC values for at most two sections: the Main section and the Auxiliary section. In the current version Auxiliary section is reserved and its parameters are set to 0x00000000.

```c
// One section of integrity check record
typedef struct {
  uint32_t pl_size; // Payload size
  uint32_t pl_crc;  // Payload CRC
} bl_icr_sect_t;

// Integrity check record
//
// This structure has a fixed size of 32 bytes. All 32-bit words are stored in
// little-endian format. CRC is calculated over first 28 bytes byte of this
// structure.
typedef struct {
  uint32_t magic;          // Magic word, BL_ICR_MAGIC (“INTG”, 0x47544E49 LE)
  uint32_t struct_rev;     // Revision of structure format
  uint32_t pl_ver;         // Payload version, 0 if not available
  bl_icr_sect_t main_sect; // Main section
  bl_icr_sect_t aux_sect;  // Auxiliary section (if available)
  uint32_t struct_crc;     // CRC of this structure using LE representation
} bl_integrity_check_rec_t;
```

## Internal Flash memory map

Memory map of the internal Flash memory is provided for STM32F469NI microcontroller. Occupied sectors are chosen to be compatible with MicroPython firmware so the specified Bootloader can replace Mboot. The only change that needs to be done is to reduce the size of FLASH_TEXT section in the platform-specific linker script to free the last two sectors for copies of Bootloader.


<table>
  <tr>
   <td><strong>Section</strong>
   </td>
   <td><strong>Sectors</strong>
   </td>
   <td><strong>Starting address</strong>
   </td>
   <td><strong>Size, bytes</strong>
   </td>
  </tr>
  <tr>
   <td><strong>Start-up code</strong>
   </td>
   <td>0
   </td>
   <td>0x08000000
   </td>
   <td>16k
   </td>
  </tr>
  <tr>
   <td>Key storage
   </td>
   <td>1
   </td>
   <td>0x08004000
   </td>
   <td>16k
   </td>
  </tr>
  <tr>
   <td>MicroPython internal FS
   </td>
   <td>2-4
   </td>
   <td>0x08008000
   </td>
   <td>96k
   </td>
  </tr>
  <tr>
   <td>MicroPython firmware
   </td>
   <td>5-21
   </td>
   <td>0x08020000
   </td>
   <td>1664k
   </td>
  </tr>
  <tr>
   <td><strong>Bootloader, copy 1</strong>
   </td>
   <td>22
   </td>
   <td>0x081C0000
   </td>
   <td>128k
   </td>
  </tr>
  <tr>
   <td><strong>Bootloader, copy 2</strong>
   </td>
   <td>23
   </td>
   <td>0x081E0000
   </td>
   <td>128k
   </td>
  </tr>
</table>
