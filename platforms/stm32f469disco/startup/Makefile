######################################
# utilities
######################################
MKDIR_P = mkdir -p

######################################
# target
######################################
TARGET = startup

######################################
# building variables
######################################
# optimization
ifeq ($(DEBUG), 1)
OPT = -Og
else
OPT = -Os
endif

#######################################
# paths
#######################################
# Build path
LOC_ROOT := $(strip $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST)))))
TARG_ROOT := $(strip $(shell dirname $(LOC_ROOT)))
CMN_ROOT := $(PWD)
BUILD_DIR_ROOT = $(CMN_ROOT)/build/$(TARGET_PLATFORM)/$(TARGET)
CMN_DIR = $(TARG_ROOT)/common
DRV_DIR = $(TARG_ROOT)/drivers
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
C_SOURCES += $(addprefix $(CORE_DIR)/,\
	bl_integrity_check.c \
	bl_util.c \
	startup_mailbox.c \
	)
# STM32F4xx HAL
C_SOURCES += $(addprefix $(DRV_DIR)/STM32F4xx_HAL_Driver/Src/,\
	stm32f4xx_hal_gpio.c \
	)
# CRC32
C_SOURCES += $(shell find $(LIB_DIR)/crc32 -name *.c)

# C includes
C_INCLUDES =  \
-I$(LOC_ROOT) \
-I$(LOC_ROOT)/config \
-I$(CMN_DIR) \
-I$(CORE_DIR) \
-I$(DRV_DIR)/CMSIS/Include \
-I$(DRV_DIR)/CMSIS/Device/ST/STM32F4xx/Include \
-I$(DRV_DIR)/STM32F4xx_HAL_Driver/Inc \
-I$(DRV_DIR)/BSP/STM32469I-Discovery \
-I$(LIB_DIR)/crc32 \

# C defines
C_DEFS =  \
PLATFORM_ID=\"$(TARGET_PLATFORM)\" \
USE_HAL_DRIVER \
STM32F469xx \
HAVE_CONFIG_H \
__BYTE_ORDER=1234 \
CRC32_USE_LOOKUP_TABLE_SLICING_BY_4 \
BL_NO_FATFS \

# ASM sources
ASM_SOURCES = $(shell find $(LOC_ROOT) -name *.s)

# AS includes
AS_INCLUDES =

# AS defines
AS_DEFS =

#######################################
# binaries
#######################################
PREFIX = arm-none-eabi-
# The gcc compiler bin path can be either defined in make command via GCC_PATH variable (> make GCC_PATH=xxx)
# either it can be added to the PATH environment variable.
ifdef GCC_PATH
CC = $(GCC_PATH)/$(PREFIX)gcc
AS = $(GCC_PATH)/$(PREFIX)gcc -x assembler-with-cpp
CP = $(GCC_PATH)/$(PREFIX)objcopy
SZ = $(GCC_PATH)/$(PREFIX)size
READELF = $(GCC_PATH)/$(PREFIX)readelf
else
CC = $(PREFIX)gcc
AS = $(PREFIX)gcc -x assembler-with-cpp
CP = $(PREFIX)objcopy
SZ = $(PREFIX)size
READELF = $(PREFIX)readelf
endif
HEX = $(CP) -O ihex
BIN = $(CP) -O binary -S

#######################################
# CFLAGS
#######################################
# cpu
CPU = -mcpu=cortex-m4

# fpu
FPU = -mfpu=fpv4-sp-d16

# float-abi
FLOAT-ABI = -mfloat-abi=hard

# mcu
MCU = $(CPU) -mthumb $(FPU) $(FLOAT-ABI)

# compile gcc flags
ASFLAGS = $(MCU) $(addprefix -D,$(AS_DEFS)) $(AS_INCLUDES) $(OPT) \
-Wall -fdata-sections -ffunction-sections

CFLAGS = $(MCU) $(addprefix -D,$(C_DEFS)) $(C_INCLUDES) $(OPT) \
-Wall -Wno-unused-function -fdata-sections -ffunction-sections

ifeq ($(DEBUG), 1)
CFLAGS += -g -gdwarf-2 -DDEBUG=1
endif

# Generate dependency information
CFLAGS += -MMD -MP -Werror -MF"$(@:%.o=%.d)"


#######################################
# LDFLAGS
#######################################
# link script
LDSCRIPT_LST = $(CMN_DIR)/memory_map.ld $(LOC_ROOT)/startup.ld
LDSCRIPTS = $(addprefix -T,$(LDSCRIPT_LST))


# libraries
LIBS = -lc -lm -lnosys
LIBDIR =
LDFLAGS = $(MCU) -specs=nano.specs $(LDSCRIPTS) $(LIBDIR) $(LIBS) -Wl,-Map=$(BUILD_DIR)/$(TARGET).map,--cref -Wl,--gc-sections -N

# default action: build all
all: $(BUILD_DIR)/$(TARGET).elf $(BUILD_DIR)/$(TARGET).hex

#######################################
# build the application
#######################################
# list of objects
OBJECTS = $(addprefix $(BUILD_DIR)/,$(notdir $(C_SOURCES:.c=.o)))
vpath %.c $(sort $(dir $(C_SOURCES)))
# list of ASM program objects
OBJECTS += $(addprefix $(BUILD_DIR)/,$(notdir $(ASM_SOURCES:.s=.o)))
vpath %.s $(sort $(dir $(ASM_SOURCES)))

$(BUILD_DIR)/%.o: %.c Makefile | $(BUILD_DIR)
	$(CC) -c $(CFLAGS) -Wa,-a,-ad,-alms=$(BUILD_DIR)/$(notdir $(<:.c=.lst)) $< -o $@

$(BUILD_DIR)/%.o: %.s Makefile | $(BUILD_DIR)
	$(AS) -c $(CFLAGS) $< -o $@

$(BUILD_DIR)/$(TARGET).elf: $(OBJECTS) Makefile
	$(CC) $(OBJECTS) $(LDFLAGS) -o $@
	$(SZ) $@

$(BUILD_DIR)/%.hex: $(BUILD_DIR)/%.elf | $(BUILD_DIR)
	$(HEX) $< $@

$(BUILD_DIR):
	mkdir -p $@

#######################################
# clean up
#######################################
clean:
	-rm -fR $(BUILD_DIR)

readelf:
	$(READELF) -a $(BUILD_DIR)/$(TARGET).elf

#######################################
# dependencies
#######################################
-include $(wildcard $(BUILD_DIR)/*.d)

# *** EOF ***
