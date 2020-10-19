######################################
# utilities
######################################
MKDIR_P = mkdir -p

######################################
# target
######################################
TARGET = bootloader

# Paths
LOC_ROOT := $(strip $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST)))))
TARG_ROOT := $(strip $(shell dirname $(LOC_ROOT)))
CMN_ROOT := $(PWD)
BUILD_DIR_ROOT = $(CMN_ROOT)/build/$(TARGET_PLATFORM)/$(TARGET)
CORE_DIR = $(CMN_ROOT)/core
LIB_DIR = $(CMN_ROOT)/lib
ifeq ($(DEBUG), 1)
BUILD_DIR = $(BUILD_DIR_ROOT)/debug
else
BUILD_DIR = $(BUILD_DIR_ROOT)/release
endif

######################################
# source
######################################
# C sources
C_SOURCES  = $(shell find $(LOC_ROOT) -name *.c)
# Bootloader core
C_SOURCES += $(shell find $(CORE_DIR) -name *.c ! -name startup_mailbox.c)
# CRC32
C_SOURCES += $(shell find $(LIB_DIR)/crc32 -name *.c)
# Crypto library
C_SOURCES += $(shell find $(LIB_DIR)/crypto -name *.c)
# libsecp256k1
C_SOURCES += $(addprefix $(LIB_DIR)/secp256k1/src/,\
	secp256k1.c \
	)
# Bech32
C_SOURCES += $(addprefix $(LIB_DIR)/bech32/,\
	segwit_addr.c \
	)
# Public keys
C_SOURCES += $(CMN_ROOT)/keys/test/test_pubkeys.c

# C includes
C_INCLUDES =  \
-I$(LOC_ROOT) \
-I$(CORE_DIR) \
-I$(CORE_DIR)/config \
-I$(CORE_DIR)/secp256k1_add \
-I$(LIB_DIR)/crc32 \
-I$(LIB_DIR)/crypto \
-I$(LIB_DIR)/secp256k1 \
-I$(LIB_DIR)/secp256k1/src \
-I$(LIB_DIR)/bech32

# C defines
C_DEFS =  \
-DTESTBENCH_PROGRESS_NEWLINE \
-DBL_NO_FATFS \
-DHAVE_CONFIG_H \
-DSECP256K1_BUILD \
-D__BYTE_ORDER=1234 \
-DCRC32_USE_LOOKUP_TABLE_SLICING_BY_8 \
-Wno-unused-function

OBJS := $(addprefix $(BUILD_DIR)/,$(notdir $(C_SOURCES:.c=.o)))
vpath %.c $(sort $(dir $(C_SOURCES)))

DEPS := $(OBJS:.o=.d)

CFLAGS = $(C_INCLUDES) -MMD -MP -Werror $(C_DEFS)

ifeq ($(DEBUG), 1)
CFLAGS += -g
LDFLAGS += -g
endif

$(BUILD_DIR)/$(TARGET).out: $(OBJS) Makefile
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

$(BUILD_DIR)/%.o: %.c Makefile
	$(MKDIR_P) $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean

clean:
	$(RM) -r $(BUILD_DIR)

-include $(DEPS)
