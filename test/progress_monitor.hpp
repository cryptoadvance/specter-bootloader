/**
 * @file       progress_monitor.hpp
 * @brief      Utility class monitoring proper use of progress callback function
 * @author     Mike Tolkachev <contact@miketolkachev.dev>
 * @copyright  Copyright 2020 Crypto Advance GmbH. All rights reserved.
 */

#ifndef PROGRESS_MONITOR_HPP_INCLUDED
/// Avoids multiple inclusion of the same file
#define PROGRESS_MONITOR_HPP_INCLUDED

#include "bl_util.h"

/// Tracks progress reported by C functions
class ProgressMonitor {
 public:
  inline ProgressMonitor(bl_cbarg_t expected_arg)
      : prev_total(-1),
        prev_complete(-1),
        expected_arg_(expected_arg),
        check_status(false),
        context_valid(true) {
    if (!inst()) {
      inst() = this;
      bl_set_progress_callback(ProgressMonitor::callback,
                               static_cast<void*>(this));
    } else {
      INFO("ERROR: progress monitor already created");
      REQUIRE(false);  // Abort test
    }
  }

  inline ~ProgressMonitor() {
    inst() = NULL;
    bl_set_progress_callback(NULL, NULL);
  }

  static void callback(void* ctx, bl_cbarg_t arg, uint32_t total,
                       uint32_t complete) {
    if (inst()) {
      if (inst()->context_valid && ctx == (void*)inst()) {
        inst()->check_args(arg, total, complete);
      } else {
        inst()->context_valid = false;
      }
    } else {
      INFO("ERROR: progress monitor not created");
      REQUIRE(false);  // Abort test
    }
  }

  inline bool is_complete() {
    return context_valid && check_status && prev_complete == prev_total;
  }

 private:
  static ProgressMonitor*& inst() {
    static ProgressMonitor* inst_ = NULL;
    return inst_;
  }

  void check_args(bl_cbarg_t arg, uint32_t total, uint32_t complete) {
    if (-1 == prev_total && -1 == prev_complete) {
      check_status = (arg == expected_arg_ && total && complete <= total);
    } else {
      check_status =
          (check_status && arg == expected_arg_ && total && complete <= total &&
           total == prev_total && complete >= prev_complete);
    }
    prev_total = total;
    prev_complete = complete;
  }

  int64_t prev_total;
  int64_t prev_complete;
  bl_cbarg_t expected_arg_;
  bool check_status;
  bool context_valid;
};

#endif  // PROGRESS_MONITOR_HPP_INCLUDED
