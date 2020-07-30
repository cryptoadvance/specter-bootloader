#define CATCH_CONFIG_MAIN
#include "catch2/catch.hpp"
#include "bl_syscalls.h"

void blsys_fatal_error(const char* text) {
  INFO(text);
  REQUIRE(false);  // Aborts test
  exit(1);
}
