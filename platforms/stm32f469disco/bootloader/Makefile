# TODO: make debug switchable

######################################
# target
######################################
TARGET = bootloader


######################################
# building variables
######################################
# optimization
OPT = -Og


#######################################
# paths
#######################################
# Build path
BUILD_DIR = build
CMN_DIR = ../common
CORE_DIR = ../../../core
LIB_DIR = ../../../lib
DRV_DIR = ../drivers

######################################
# source
######################################
# C sources
C_SOURCES =  \
main.c \
stm32f4xx_it.c \
system_stm32f4xx.c

ifeq ($(DEBUG), 1)
C_SOURCES += debug_startup.c
endif

# Common files
C_SOURCES += $(addprefix $(CMN_DIR)/,\
	)

# Bootloader core
C_SOURCES += $(addprefix $(CORE_DIR)/,\
	secp256k1_add/ext_callbacks.c \
	startup_mailbox.c \
	)

# STM32F4xx HAL
C_SOURCES += $(addprefix $(DRV_DIR)/STM32F4xx_HAL_Driver/Src/stm32f4xx_,\
	hal.c \
	hal_cortex.c \
	hal_crc.c \
	hal_dma.c \
	hal_dma2d.c \
	hal_dma_ex.c \
	hal_dsi.c \
	hal_flash.c \
	hal_flash_ex.c \
	hal_flash_ramfunc.c \
	hal_gpio.c \
	hal_ltdc.c \
	hal_ltdc_ex.c \
	hal_pwr.c \
	hal_pwr_ex.c \
	hal_rcc.c \
	hal_rcc_ex.c \
  hal_sd.c \
	hal_sdram.c \
	hal_uart.c \
	ll_fmc.c \
	ll_sdmmc.c \
	)

# STM32469I-Discovery BSP
C_SOURCES += $(addprefix $(DRV_DIR)/BSP/STM32469I-Discovery/,\
	stm32469i_discovery.c \
	stm32469i_discovery_lcd.c \
	stm32469i_discovery_sd.c \
	stm32469i_discovery_sdram.c \
	)
C_SOURCES += $(DRV_DIR)/BSP/Components/otm8009a/otm8009a.c

# CRC32
C_SOURCES += $(addprefix $(LIB_DIR)/crc32/,\
	crc32.c \
	)

# FatFs
C_SOURCES += $(addprefix $(LIB_DIR)/fatfs/source/,\
	ff.c \
	ffsystem.c \
	ffunicode.c \
	)

# FatFs IO layer
C_SOURCES += $(addprefix $(DRV_DIR)/fatfs_io/,\
	diskio_gen_drv.c \
	ff_gen_drv.c \
	sd_diskio.c \
	)

# Crypto library
C_SOURCES += $(addprefix $(LIB_DIR)/crypto/,\
	memzero.c \
	sha2.c \
	)

# libsecp256k1
C_SOURCES += $(addprefix $(LIB_DIR)/secp256k1/src/,\
	secp256k1.c \
	)

# C includes
C_INCLUDES =  \
-I$(PWD) \
-Iconfig \
-I$(CMN_DIR) \
-I$(CORE_DIR) \
-I$(CORE_DIR)/config \
-I$(CORE_DIR)/secp256k1_add \
-I$(DRV_DIR)/CMSIS/Include \
-I$(DRV_DIR)/CMSIS/Device/ST/STM32F4xx/Include \
-I$(DRV_DIR)/STM32F4xx_HAL_Driver/Inc \
-I$(DRV_DIR)/BSP/STM32469I-Discovery \
-I$(LIB_DIR)/crc32 \
-I$(DRV_DIR)/fatfs_io \
-I$(LIB_DIR)/fatfs/source \
-I$(LIB_DIR)/crypto \
-I$(LIB_DIR)/secp256k1 \
-I$(LIB_DIR)/secp256k1/src

# C defines
C_DEFS =  \
-DUSE_HAL_DRIVER \
-DSTM32F469xx \
-DHAVE_CONFIG_H \
-DSECP256K1_BUILD \
-D__BYTE_ORDER=1234 \
-DCRC32_USE_LOOKUP_TABLE_SLICING_BY_8 \
-Wno-unused-function

# TODO: remove if unneded
#-Wno-nonnull-compare

# ASM sources
ASM_SOURCES =  \
startup_stm32f469xx.s

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
ASFLAGS = $(MCU) $(AS_DEFS) $(AS_INCLUDES) $(OPT) -Wall -fdata-sections -ffunction-sections

CFLAGS = $(MCU) $(C_DEFS) $(C_INCLUDES) $(OPT) -Wall -fdata-sections -ffunction-sections

ifeq ($(DEBUG), 1)
CFLAGS += -g -gdwarf-2
endif

# Generate dependency information
CFLAGS += -MMD -MP -MF"$(@:%.o=%.d)"


#######################################
# LDFLAGS
#######################################
# link script
ifeq ($(DEBUG), 1)
LDSCRIPT = bootloader_debug.ld
else
LDSCRIPT = bootloader.ld
endif


# libraries
LIBS = -lc -lm -lnosys
LIBDIR =
LDFLAGS = $(MCU) -specs=nano.specs -T$(LDSCRIPT) $(LIBDIR) $(LIBS) -Wl,-Map=$(BUILD_DIR)/$(TARGET).map,--cref -Wl,--gc-sections -N

# default action: build all
all: $(BUILD_DIR)/$(TARGET).elf $(BUILD_DIR)/$(TARGET).hex $(BUILD_DIR)/$(TARGET).bin


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

$(BUILD_DIR)/%.bin: $(BUILD_DIR)/%.elf | $(BUILD_DIR)
	$(BIN) $< $@

$(BUILD_DIR):
	mkdir $@

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
