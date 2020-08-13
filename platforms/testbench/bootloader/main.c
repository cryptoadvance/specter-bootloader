#include <stdio.h>
#include <stdlib.h>
#include "bootloader.h"
#include "bl_syscalls.h"

int main(int argc, char* argv[]) {
  printf("\nBootloader host test bench");

  bl_addr_t bl_addr = 0U;
  if (!blsys_flash_map_get_items(1, bl_flash_bootloader_copy1_base, &bl_addr)) {
    blsys_fatal_error("Cannot get Bootloader address");
  }

  printf("\nStarting Bootloader");
  bl_args_t args = {.loaded_from = bl_addr};
  bl_status_t status = bootloader_run(&args, bl_flag_no_args_crc_check);
  printf("\nBootloader exited with status: %s", bootloader_status_text(status));
}
