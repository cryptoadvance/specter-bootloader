# List of all supported platforms
PLATFORMS = stm32f469disco testbench

# Select target platform by first argument
FIRST_ARG = $(firstword $(MAKECMDGOALS))
ifeq ($(findstring $(FIRST_ARG),$(PLATFORMS)),$(FIRST_ARG))
	TARGET_PLATFORM = $(FIRST_ARG)
endif

 # Create argument list for target Makefile
ifdef TARGET_PLATFORM
  BOOTLOADER_MAKEFILE = platforms/$(TARGET_PLATFORM)/bootloader/Makefile
	STARTUP_MAKEFILE = platforms/$(TARGET_PLATFORM)/startup/Makefile
  RUN_ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
  $(eval $(RUN_ARGS):;@:)
endif

# Pubkeys folder: keys/selfsigned/pubkeys.c
# Create the file with keys you want to use for firmware signing
KEYS ?= selfsigned

.PHONY: $(PLATFORMS) clean test unit_tests


clean:
	-rm -fR build

test:
	@$(MAKE) -f test/Makefile test

unit_tests:
	@$(MAKE) -f test/Makefile

stm32f469disco:
	@test -f keys/$(KEYS)/pubkeys.c || (echo ERROR: ./$(KEYS)/pubkey.c file does not exist. Create it or define different KEYS parameter; exit 1;)
	@$(MAKE) -f $(STARTUP_MAKEFILE) $(RUN_ARGS) TARGET_PLATFORM=$(TARGET_PLATFORM)
	@$(MAKE) -f $(BOOTLOADER_MAKEFILE) $(RUN_ARGS) TARGET_PLATFORM=$(TARGET_PLATFORM) KEYS=$(KEYS)

testbench:
	$(shell echo Test Bench)
	@$(MAKE) -f $(BOOTLOADER_MAKEFILE) $(RUN_ARGS) TARGET_PLATFORM=$(TARGET_PLATFORM)
