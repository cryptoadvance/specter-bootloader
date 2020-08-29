/**
 * @file       gui.h
 * @brief      Graphical user interface elements for the Bootloader
 * @author     Mike Tolkachev <contact@miketolkachev.dev>
 * @copyright  Copyright 2020 Crypto Advance GmbH. All rights reserved.
 */

#ifndef GUI_H_INCLUDED
#define GUI_H_INCLUDED

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "bl_syscalls.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initializes GUI and and reliant hardware
 *
 * NOTE: Actual hardware initialization is partially or fully deferred until
 * the first use of GUI to minimize the impact on the Main firmware when no
 * upgrading is performed.
 */
void gui_init(void);

/**
 * De-initialises GUI freeing hardware resources
 */
void gui_deinit(void);

/**
 * Updates progress bar and accompanying text fields
 *
 * @param caption       caption text
 * @param operation     text describing the current operation
 * @param percent_x100  percent of completeness in 0.01% units
 * @return              true if successful
 */
bool gui_update_progress(const char* caption, const char* operation,
                         uint32_t percent_x100);

/**
 * Shows alert pop-up window
 *
 * @param type         alert type
 * @param caption      alert caption text
 * @param text         alert text
 * @param user_action  text describing required user action, may be NULL
 * @return             true if successful
 */
bool gui_show_alert(blsys_alert_type_t type, const char* caption,
                    const char* text, const char* user_action);

/**
 * Hides alert pop-up window
 */
void gui_hide_alert(void);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // GUI_H_INCLUDED
