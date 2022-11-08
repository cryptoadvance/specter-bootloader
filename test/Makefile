######################################
# utilities
######################################
MKDIR_P = mkdir -p

######################################
# target
######################################
TARGET = test_runner

# Paths
LOC_ROOT := $(strip $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST)))))
CMN_ROOT := $(PWD)
BUILD_DIR_ROOT = $(CMN_ROOT)/build/$(TARGET)
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
# C++ sources
CPP_SOURCES  = $(shell find $(LOC_ROOT) -name *.cpp)
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

# C includes
C_INCLUDES =  \
-I$(LOC_ROOT) \
-I$(LOC_ROOT)/catch2 \
-I$(CORE_DIR) \
-I$(CORE_DIR)/config \
-I$(CORE_DIR)/secp256k1_add \
-I$(LIB_DIR)/crc32 \
-I$(LIB_DIR)/crypto \
-I$(LIB_DIR)/secp256k1 \
-I$(LIB_DIR)/secp256k1/include \
-I$(LIB_DIR)/secp256k1/src \
-I$(LIB_DIR)/bech32

# C defines
C_DEFS =  \
UNIT_TEST \
BL_NO_FATFS \
HAVE_CONFIG_H \
SECP256K1_BUILD \
__BYTE_ORDER=1234 \
CRC32_USE_LOOKUP_TABLE_SLICING_BY_8 \

OBJS = $(addprefix $(BUILD_DIR)/,$(notdir $(C_SOURCES:.c=.o)))
vpath %.c $(sort $(dir $(C_SOURCES)))

OBJS += $(addprefix $(BUILD_DIR)/,$(notdir $(CPP_SOURCES:.cpp=.o)))
vpath %.cpp $(sort $(dir $(CPP_SOURCES)))

DEPS := $(OBJS:.o=.d)

CFLAGS = $(C_INCLUDES) -MMD -MP -Werror -Wno-unused-function \
$(addprefix -D,$(C_DEFS))

CPPFLAGS = -std=c++14
LDFLAGS ?= -lstdc++ -lm -ldl

ifeq ($(DEBUG), 1)
CFLAGS += -g -DDEBUG=1
LDFLAGS += -g
endif

$(BUILD_DIR)/$(TARGET).out: $(OBJS) Makefile
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

$(BUILD_DIR)/%.o: %.c Makefile
	$(MKDIR_P) $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/%.o: %.cpp Makefile
	$(MKDIR_P) $(dir $@)
	$(CXX) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

.PHONY: clean test

test: $(BUILD_DIR)/$(TARGET).out
	@$(BUILD_DIR)/$(TARGET).out

clean:
	$(RM) -r $(BUILD_DIR)

-include $(DEPS)
