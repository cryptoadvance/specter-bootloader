/**
 * @file       test_pubkeys.c
 * @brief      Test public keys
 * @author     Mike Tolkachev <contact@miketolkachev.dev>
 * @copyright  Copyright 2020 Crypto Advance GmbH. All rights reserved.
 */

#include "bootloader.h"

// List of Vendor public keys
static const bl_pubkey_t vendor_pubkey_list[] = {
    // The following public keys are exported from individual PEM files located
    // in the "keys/test" directory.

    // Corresponding private key: "vend1.pem"
    {.bytes = {0x04U, 0xC4U, 0x11U, 0x3FU, 0x2CU, 0x96U, 0x1FU, 0xC9U, 0xC5U,
               0x25U, 0x23U, 0x44U, 0xF6U, 0x26U, 0x6CU, 0x8AU, 0xB3U, 0x34U,
               0xD4U, 0x1DU, 0x6DU, 0x7FU, 0xE9U, 0x23U, 0x79U, 0x51U, 0x51U,
               0x52U, 0x2FU, 0x7CU, 0x66U, 0x96U, 0xC6U, 0xDFU, 0x00U, 0x89U,
               0x9AU, 0x6FU, 0x96U, 0x99U, 0xF1U, 0xFFU, 0xD3U, 0x98U, 0x6EU,
               0x0BU, 0xC0U, 0xDEU, 0x79U, 0xF1U, 0xDFU, 0xF0U, 0x05U, 0xC5U,
               0x55U, 0x95U, 0x6DU, 0x25U, 0x15U, 0x21U, 0xBCU, 0x58U, 0xACU,
               0x1AU, 0x9BU}},
    // Corresponding private key: "vend2.pem"
    {.bytes = {0x04U, 0x59U, 0x86U, 0x95U, 0xD1U, 0x57U, 0x8AU, 0xB1U, 0xFBU,
               0xADU, 0xEBU, 0x53U, 0x68U, 0xE3U, 0x13U, 0xB6U, 0xC6U, 0x3BU,
               0x83U, 0xD3U, 0x0EU, 0x35U, 0x30U, 0x07U, 0x32U, 0x91U, 0x4CU,
               0xECU, 0x3CU, 0xD9U, 0x8DU, 0xE2U, 0xBDU, 0xE6U, 0x4EU, 0x2CU,
               0xA4U, 0x3DU, 0xBFU, 0xF4U, 0x3EU, 0xD5U, 0x3BU, 0xF2U, 0xACU,
               0x40U, 0x08U, 0x96U, 0xE7U, 0x4CU, 0x36U, 0x99U, 0x9DU, 0xBCU,
               0x36U, 0xE1U, 0x46U, 0x29U, 0xD8U, 0xFDU, 0x58U, 0xAEU, 0x7BU,
               0xEDU, 0x80U}},
    // Corresponding private key: "vend3.pem"
    {.bytes = {0x04U, 0x4FU, 0xC6U, 0x8BU, 0x8CU, 0xA5U, 0xCEU, 0x74U, 0xC6U,
               0x50U, 0xC4U, 0x69U, 0x0AU, 0x62U, 0x55U, 0xDDU, 0x86U, 0xF3U,
               0x25U, 0x66U, 0xA1U, 0x33U, 0x62U, 0x0BU, 0x83U, 0x4CU, 0x60U,
               0x09U, 0x6FU, 0xD2U, 0x3FU, 0xC0U, 0x1FU, 0xA0U, 0xE7U, 0x19U,
               0x8BU, 0x16U, 0x39U, 0xE4U, 0x65U, 0x20U, 0x7AU, 0xB1U, 0x77U,
               0x77U, 0x72U, 0x0AU, 0x35U, 0x87U, 0xE3U, 0x15U, 0x8AU, 0xCEU,
               0x56U, 0xADU, 0x69U, 0x14U, 0xA9U, 0xB8U, 0x58U, 0x13U, 0x72U,
               0xDEU, 0x5EU}},

    // The following public keys are exported from a BIP32 wallet with the seed:
    // "ripple ask sword jaguar federal fork awake hundred galaxy sadness ice
    //  live"

    // Corresponds to m/0/0, 1H1Yk1PBigBezZZ1712pyoguX6G2uznySV
    {.bytes = {0x04U, 0xC1U, 0x03U, 0x4AU, 0xDCU, 0x4BU, 0x7EU, 0x3AU, 0xC0U,
               0x65U, 0x53U, 0x7CU, 0xF9U, 0xF3U, 0xA9U, 0xF6U, 0x52U, 0x5BU,
               0x53U, 0xEDU, 0xBDU, 0xA8U, 0x38U, 0x4FU, 0x23U, 0xF3U, 0x76U,
               0x08U, 0x7BU, 0xEFU, 0x93U, 0x9DU, 0x32U, 0x4DU, 0x88U, 0xE5U,
               0xC8U, 0x86U, 0xABU, 0x32U, 0x9DU, 0xD5U, 0x72U, 0x0EU, 0xCBU,
               0xD5U, 0x95U, 0x0DU, 0xADU, 0xB6U, 0xBEU, 0x13U, 0x7AU, 0x82U,
               0x3BU, 0x41U, 0xC3U, 0x4DU, 0xF4U, 0xE5U, 0x8DU, 0x1EU, 0x14U,
               0x76U, 0x3FU}},
    // Corresponds to m/0/1, 1M6CfqkahaHJvPhp34QFMGEsTmdLATgkPf
    {.bytes = {0x04U, 0xC6U, 0x77U, 0x07U, 0x51U, 0x4CU, 0x44U, 0xBCU, 0xE9U,
               0xA4U, 0xE0U, 0x86U, 0x08U, 0x21U, 0x9FU, 0x9AU, 0xCAU, 0x26U,
               0xA7U, 0xB8U, 0xD4U, 0x02U, 0xEBU, 0x6BU, 0xF0U, 0x8CU, 0xF0U,
               0xEBU, 0x5AU, 0xCAU, 0x0AU, 0xA6U, 0x8BU, 0x94U, 0x9DU, 0xFCU,
               0xF8U, 0x22U, 0x57U, 0xFCU, 0x91U, 0xD9U, 0xDAU, 0x0AU, 0xE3U,
               0x70U, 0xD0U, 0x2BU, 0x51U, 0xDFU, 0x24U, 0x40U, 0xA6U, 0x76U,
               0x31U, 0xB7U, 0x07U, 0x4EU, 0x0CU, 0x5EU, 0x51U, 0xF8U, 0xB6U,
               0x7BU, 0x8CU}},
    // Corresponds to m/0/2, 17PW4JcbNnRwKCaCPadgnnevWhgQN6oSY6
    {.bytes = {0x04U, 0xFCU, 0x83U, 0xDFU, 0xF8U, 0xB8U, 0x4EU, 0x13U, 0x42U,
               0x5EU, 0x9BU, 0xB6U, 0x0FU, 0xACU, 0x55U, 0x79U, 0xBDU, 0x5BU,
               0x10U, 0xD7U, 0x27U, 0x69U, 0x2EU, 0xABU, 0x1EU, 0xB8U, 0xE4U,
               0x0FU, 0x61U, 0xADU, 0x5DU, 0xAEU, 0x29U, 0xF6U, 0xA1U, 0x5CU,
               0xAEU, 0xC2U, 0x87U, 0xB1U, 0x6EU, 0x7EU, 0x0EU, 0xDBU, 0x2BU,
               0x9BU, 0x6CU, 0x75U, 0xC9U, 0x49U, 0x0DU, 0x36U, 0x2FU, 0x28U,
               0x42U, 0xD5U, 0x6DU, 0xF8U, 0x84U, 0x40U, 0x61U, 0x2FU, 0x2FU,
               0xBDU, 0x81U}},
    BL_PUBKEY_END_OF_LIST};

// List of Maintainer public keys
static const bl_pubkey_t maintainer_pubkey_list[] = {
    // Corresponding private key: "maint1.pem"
    {.bytes = {0x04U, 0x15U, 0x07U, 0x2AU, 0x53U, 0x1DU, 0xDAU, 0x48U, 0x71U,
               0xCBU, 0x82U, 0xB2U, 0xDFU, 0xD8U, 0x9CU, 0x88U, 0x7EU, 0xB7U,
               0xDDU, 0xC6U, 0x7DU, 0x3EU, 0xDFU, 0xDAU, 0x16U, 0x48U, 0xBAU,
               0xF3U, 0xBDU, 0xACU, 0xFDU, 0x36U, 0x8DU, 0x63U, 0x9EU, 0x4CU,
               0x06U, 0xC1U, 0x03U, 0x08U, 0xE8U, 0xC3U, 0x51U, 0x9BU, 0x25U,
               0xBCU, 0x22U, 0x90U, 0x04U, 0xDFU, 0x7FU, 0x9EU, 0x05U, 0x8CU,
               0xF7U, 0xFBU, 0xD2U, 0x45U, 0x18U, 0xDDU, 0x41U, 0xB3U, 0x8FU,
               0x72U, 0xCCU}},
    // Corresponding private key: "maint2.pem"
    {.bytes = {0x04U, 0xDBU, 0x9CU, 0x6CU, 0xD2U, 0x45U, 0xEBU, 0x3FU, 0x52U,
               0x57U, 0xBEU, 0xACU, 0x08U, 0xDBU, 0x76U, 0x47U, 0x9AU, 0x65U,
               0x2CU, 0xA3U, 0xE7U, 0xAFU, 0x7FU, 0xF0U, 0x63U, 0x74U, 0xDDU,
               0xE3U, 0x20U, 0xD1U, 0x5AU, 0xF5U, 0xB4U, 0x71U, 0xD6U, 0xC1U,
               0x5AU, 0xA2U, 0x35U, 0x4DU, 0x9AU, 0xE7U, 0xA0U, 0x29U, 0xF4U,
               0x0FU, 0xA9U, 0xA5U, 0x30U, 0x51U, 0x44U, 0x13U, 0xC2U, 0x14U,
               0xC5U, 0x1AU, 0x1BU, 0xB5U, 0xE2U, 0xF4U, 0xB7U, 0x5DU, 0x1AU,
               0xCFU, 0x21U}},
    // Corresponding private key: "maint3.pem"
    {.bytes = {0x04U, 0xAAU, 0x05U, 0x7DU, 0x05U, 0x22U, 0x49U, 0xC8U, 0x91U,
               0x87U, 0x35U, 0x63U, 0x0CU, 0xCEU, 0x09U, 0x89U, 0x0CU, 0x4CU,
               0x4AU, 0xB4U, 0xC5U, 0x06U, 0x5AU, 0x35U, 0xBDU, 0x86U, 0xC4U,
               0x37U, 0x1AU, 0x8EU, 0x40U, 0x1DU, 0x98U, 0xDBU, 0x41U, 0xF6U,
               0xCDU, 0x35U, 0xD7U, 0xB5U, 0x60U, 0xC3U, 0x59U, 0x01U, 0x48U,
               0xB4U, 0xC3U, 0xD4U, 0xC5U, 0x35U, 0x3CU, 0x4CU, 0xC3U, 0x9BU,
               0x19U, 0x94U, 0x02U, 0x0FU, 0x6BU, 0x1DU, 0x38U, 0x6AU, 0x9BU,
               0xCDU, 0xD8U}},
    // Corresponding private key: "maint4.pem"
    {.bytes = {0x04U, 0x48U, 0x06U, 0xA3U, 0xEBU, 0xA5U, 0xD6U, 0x17U, 0x27U,
               0xC8U, 0x7EU, 0x34U, 0x38U, 0x8CU, 0xE9U, 0x2EU, 0x8FU, 0x15U,
               0xA4U, 0x79U, 0xC9U, 0xA4U, 0xF1U, 0xF6U, 0x68U, 0x27U, 0x64U,
               0xDBU, 0x0AU, 0x2EU, 0x8AU, 0x66U, 0x7EU, 0xCAU, 0x52U, 0x5DU,
               0xBEU, 0xF9U, 0xAAU, 0xF5U, 0x9EU, 0x0AU, 0x3DU, 0x7AU, 0x98U,
               0x9EU, 0xEDU, 0x31U, 0x4AU, 0xD9U, 0x34U, 0x5FU, 0xD9U, 0x9EU,
               0x80U, 0xAFU, 0xCAU, 0x20U, 0x0FU, 0x75U, 0x16U, 0x0CU, 0x4EU,
               0x6EU, 0x6FU}},
    // Corresponding private key: "maint5.pem"
    {.bytes = {0x04U, 0x72U, 0x41U, 0x81U, 0xCCU, 0xD6U, 0xC2U, 0x59U, 0x7EU,
               0xCAU, 0xD1U, 0x27U, 0x8BU, 0x99U, 0xF3U, 0x5FU, 0xAFU, 0x3DU,
               0xB1U, 0x4FU, 0x3BU, 0x3DU, 0xB4U, 0x20U, 0x70U, 0x25U, 0x75U,
               0x5EU, 0x21U, 0x6BU, 0xD0U, 0x85U, 0xF1U, 0x75U, 0x4FU, 0x09U,
               0x11U, 0x97U, 0x56U, 0x9CU, 0xE9U, 0x5AU, 0x7EU, 0x2EU, 0x22U,
               0xEDU, 0xAEU, 0x46U, 0x22U, 0x85U, 0x45U, 0x98U, 0x34U, 0x40U,
               0x58U, 0x7DU, 0xE9U, 0xD2U, 0x78U, 0xA6U, 0x08U, 0xCAU, 0x86U,
               0xCBU, 0xE2U}},
    BL_PUBKEY_END_OF_LIST};

// Test set of public keys and signature thresholds
const bl_pubkey_set_t bl_pubkey_set = {
    .vendor_pubkeys = vendor_pubkey_list,
    .vendor_pubkeys_size = sizeof(vendor_pubkey_list),
    .maintainer_pubkeys = maintainer_pubkey_list,
    .maintainer_pubkeys_size = sizeof(maintainer_pubkey_list),
    .bootloader_sig_threshold = 2,
    .main_fw_sig_threshold = 3};
