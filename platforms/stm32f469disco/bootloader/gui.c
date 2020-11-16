/**
 * @file       gui.c
 * @brief      Graphical user interface elements for the Bootloader
 * @author     Mike Tolkachev <contact@miketolkachev.dev>
 * @copyright  Copyright 2020 Crypto Advance GmbH. All rights reserved.
 *
 * Progress bar drawing based on the "min_display" example by Stepan Snigirev
 * <stepan@cryptoadvance.io>
 */

#include <string.h>
#include <ctype.h>
#include "gui.h"
#include "stm32469i_discovery.h"
#include "stm32469i_discovery_lcd.h"
#include "stm32469i_discovery_sdram.h"

/// Width of LCD in pixels
#define LCD_WIDTH 480U
/// Height of LCD in pixels
#define LCD_HEIGHT 800U
/// Bytes per pixel
#define LCD_BYTE_PER_PIXEL 4U

/// LTDC background layer address
#define LCD_BG_LAYER_ADDRESS LCD_FB_START_ADDRESS
/// LTDC foreground layer address
#define LCD_FG_LAYER_ADDRESS \
  (LCD_BG_LAYER_ADDRESS + (LCD_WIDTH * LCD_HEIGHT * LCD_BYTE_PER_PIXEL))

/// Main text color: smoke white
#define COLOR_TEXT 0xFFF0F0F0U
/// Low intensity text color: bluish light gray
#define COLOR_TEXT_LOW 0xFF808A96U
/// Background color: muted dark blue
#define COLOR_BG 0xFF182432U
/// Color of controls: bluish gray
#define COLOR_CONTROL 0xFF4B6073U
/// Accent color: bright blue
#define COLOR_ACCENT 0xFF0073B8U
/// Color of inactive GUI elements: dark gray
#define COLOR_INACTIVE 0xFF28292DU
/// Caption background for error alerts
#define COLOR_ERROR_BG 0xFF802020U
/// Caption background for warning alerts
#define COLOR_WARNING_BG 0xFF885020U
/// Caption background for information alerts
#define COLOR_INFO_BG 0xFF2C374BU

/// Width of the progress bar
#define PROGRESS_WIDTH 380U
/// Heigh of the progress bar
#define PROGRESS_HEIGHT 20U
/// Progress bar location: y
#define PROGRESS_Y 250U
/// Caption text location
#define PAGE_CAPTION_Y 40U
/// Pointer to font used to render page caption text
#define PAGE_CAPTION_FONT (&Font24)
/// Height of page caption
#define PAGE_CAPTION_HEIGHT (2 * PAGE_CAPTION_Y + (PAGE_CAPTION_FONT)->Height)
/// Location of caption in Progress page
#define PROGRESS_CAPTION_Y (PROGRESS_Y - 40U)
/// Location of caption text in Progress page
#define PROGRESS_OPERATION_Y (PROGRESS_Y + PROGRESS_HEIGHT + 30U)
/// Alert text location: x
#define ALERT_TEXT_X 10U
/// Alert text location: y
#define ALERT_TEXT_Y 150U
/// Alert text y offset from the last line of alert text
#define ALERT_ACTION_Y_OFF 50U

/// GUI page identifier
typedef enum gui_page_t {
  gui_page_progress = 0,  ///< Progress page
  gui_page_alert,         ///< Alert page
  gui_n_pages,            ///< Number of pages (not a page)
  gui_page_none = -1      ///< Reserved value meaning "no page" (not a page)
} gui_page_t;

/// Flags affecting text rendering
typedef enum text_render_flags_t {
  text_render_uppercase = (1 << 0),
  text_render_multiline = (1 << 1)
} text_render_flags_t;

/// Colors of caption packground for the Alert page
static const uint32_t alert_caption_bg[bl_nalerts] = {
    [bl_alert_info] = COLOR_INFO_BG,
    [bl_alert_warning] = COLOR_WARNING_BG,
    [bl_alert_error] = COLOR_ERROR_BG};

/// Statically allocated local context
static struct {
  /// Flag indicating that LCD is initialized
  bool lcd_initialized;
  /// Currently displayed GUI page
  gui_page_t displayed_page;
} ctx = {.lcd_initialized = false, .displayed_page = gui_page_none};

void gui_init(void) {
  memset(&ctx, 0, sizeof(ctx));
  ctx.lcd_initialized = false;
  ctx.displayed_page = gui_page_none;
}

void gui_deinit(void) {
  if (ctx.lcd_initialized) {
    BSP_LCD_DisplayOff();
    BSP_LCD_Reset();
    BSP_LCD_MspDeInit();
    BSP_SDRAM_DeInit();
    ctx.lcd_initialized = false;
  }
}

/**
 * Initializes LCD layer
 *
 * @param  LayerIndex: Layer foreground or background
 * @param  FB_Address: Layer frame buffer
 */
static void lcd_layer_init(uint16_t LayerIndex, uint32_t FB_Address) {
  // Initialize background layer
  BSP_LCD_LayerDefaultInit(LayerIndex, FB_Address);
  BSP_LCD_SetTransparency(LayerIndex, 0xFFU);
  BSP_LCD_ResetColorKeying(LayerIndex);
  BSP_LCD_SelectLayer(LayerIndex);
  BSP_LCD_SetBackColor(COLOR_BG);
  BSP_LCD_Clear(COLOR_BG);
  BSP_LCD_SetLayerVisible(LayerIndex, ENABLE);
}

/**
 * Initializes LCD if it is not yet done
 */
static void lcd_init_if_needed(void) {
  if (!ctx.lcd_initialized) {
    // Initialize LCD controller and turn of the display
    BSP_LCD_InitEx(LCD_ORIENTATION_PORTRAIT);
    BSP_LCD_DisplayOff();

    // Initialize layers
    lcd_layer_init(LTDC_ACTIVE_LAYER_BACKGROUND, LCD_BG_LAYER_ADDRESS);
    lcd_layer_init(LTDC_ACTIVE_LAYER_FOREGROUND, LCD_FG_LAYER_ADDRESS);

    // Hide foreground layer and select background layer for drawing
    BSP_LCD_SetLayerVisible(LTDC_ACTIVE_LAYER_FOREGROUND, DISABLE);
    BSP_LCD_SelectLayer(LTDC_ACTIVE_LAYER_BACKGROUND);

    // Turn the display on
    HAL_Delay(100);
    BSP_LCD_DisplayOn();
    ctx.displayed_page = gui_page_none;
    ctx.lcd_initialized = true;
  }
}

/**
 * Draws a progress bar
 *
 * @param x_pos         x position
 * @param y_pos         y position
 * @param width         width in pixels
 * @param height        height in pixels
 * @param percent_x100  percent of completeness in 0.01% units
 * @return              true if successful
 */
static bool draw_progress_bar(uint16_t x_pos, uint16_t y_pos, uint16_t width,
                              uint16_t height, uint32_t percent_x100) {
  if (width > 4U && height > 4U && x_pos + width < LCD_WIDTH &&
      y_pos + height < LCD_HEIGHT) {
    uint16_t fill_width = width - 4U;
    uint16_t fill_height = height - 4U;
    uint32_t active_width = percent_x100 * fill_width / 10000U;
    uint16_t inactive_width = fill_width - active_width;

    // Draw border with rounded corners
    BSP_LCD_SetTextColor(COLOR_CONTROL);
    BSP_LCD_DrawHLine(x_pos + 1U, y_pos, width - 2U);
    BSP_LCD_DrawHLine(x_pos + 1U, y_pos + 1, width - 2U);
    BSP_LCD_DrawHLine(x_pos + 1U, y_pos + height - 1U, width - 2U);
    BSP_LCD_DrawHLine(x_pos + 1U, y_pos + height - 2U, width - 2U);
    BSP_LCD_DrawVLine(x_pos, y_pos + 1U, height - 2U);
    BSP_LCD_DrawVLine(x_pos + 1, y_pos + 1U, height - 2U);
    BSP_LCD_DrawVLine(x_pos + width - 1U, y_pos + 1U, height - 2U);
    BSP_LCD_DrawVLine(x_pos + width - 2U, y_pos + 1U, height - 2U);

    // Fill active and inactive parts
    if (active_width) {
      BSP_LCD_SetTextColor(COLOR_ACCENT);
      BSP_LCD_FillRect(x_pos + 2U, y_pos + 2U, active_width, fill_height);
    }
    if (inactive_width) {
      BSP_LCD_SetTextColor(COLOR_INACTIVE);
      BSP_LCD_FillRect(x_pos + active_width + 2U, y_pos + 2U, inactive_width,
                       fill_height);
    }
    return true;
  }
  return false;
}

/**
 * Returns length of printable part of a string
 *
 * @param text   text string
 * @param limit  maximum number of character that could be printed
 * @param flags  text rendering flags, only text_render_multiline is used
 * @return       size
 */
static size_t printable_text_len(const char* text, size_t limit,
                                 uint32_t flags) {
  if (text && limit) {
    size_t len = 0U;
    size_t whole_word_len = 0U;
    const char* p_text = text;
    bool prev_space = false;
    while (*p_text != '\0' && *p_text != '\n' && *p_text != '\r' &&
           len <= limit) {
      if (' ' == *p_text) {
        if (!prev_space) {
          whole_word_len = len;
          prev_space = true;
        }
      } else {
        prev_space = false;
      }
      ++len;
      ++p_text;
    }
    if (flags & text_render_multiline) {
      return len <= limit ? len : whole_word_len;
    }
    return len <= limit ? len : limit;
  }
  return 0U;
}

/**
 * Creates a new string copying characters from source aligning with spaces
 *
 * @param dst         destination buffer
 * @param dst_size    size of destination buffer
 * @param src         source string
 * @param src_size    number of characters to copy from the source string
 * @param align_size  boundary to which the string is aligned
 * @param mode        alignment mode
 * @return            true if successful
 */
static bool strncpy_aligned(char* dst, size_t dst_size, const char* src,
                            size_t src_size, size_t align_size,
                            Text_AlignModeTypdef mode) {
  if (dst && src && dst_size < SIZE_MAX - 1U && dst_size + 1U >= src_size &&
      dst_size + 1U >= align_size) {
    if (!src_size) {
      return true;
    }
    if (src_size >= align_size) {
      memcpy(dst, src, align_size);
      *(dst + align_size) = '\0';
    } else {
      size_t pad_size = align_size - src_size;
      switch (mode) {
        case RIGHT_MODE:
          memset(dst, ' ', pad_size);
          memcpy(dst + pad_size, src, src_size);
          *(dst + pad_size + src_size) = '\0';
          break;

        case LEFT_MODE:
          memcpy(dst, src, src_size);
          memset(dst + src_size, ' ', pad_size);
          *(dst + src_size + pad_size) = '\0';
          break;

        case CENTER_MODE:
        default:
          memcpy(dst, src, src_size);
          *(dst + src_size) = '\0';
          break;
      }
    }
    return true;
  }
  return false;
}

/**
 * Converts string to upper case in-place
 *
 * @param str  pointer to string to process
 */
static void str_toupper_inplace(char* str) {
  char* p_str = str;
  while (*p_str != '\0') {
    *p_str = toupper(*p_str);
    ++p_str;
  }
}

/**
 * Draws a single text line
 *
 * @param x_pos     x position
 * @param y_pos     y position
 * @param mode      alignment mode
 * @param p_font    pointer to font used to render the text
 * @param color     text color
 * @param text      test string to render
 * @param flags     text rendering flags
 * @param p_n_syms  pointer to variable receiving number of rendered symbols, if
 *                  not NULL
 * @return          true if successful
 */
static bool draw_text_line(uint16_t x_pos, uint16_t y_pos,
                           Text_AlignModeTypdef mode, const sFONT* p_font,
                           uint32_t color, const char* text, uint32_t flags,
                           size_t* p_n_syms) {
  if (p_font && text && x_pos < LCD_WIDTH && y_pos < LCD_HEIGHT) {
    char text_buf[100 + 1];
    size_t line_syms = (size_t)(LCD_WIDTH - x_pos) / p_font->Width;
    if (line_syms + 1U > sizeof(text_buf)) {
      return false;
    }
    size_t text_len = printable_text_len(text, line_syms, flags);
    if (p_n_syms) {
      *p_n_syms = text_len;
    }
    if (!text_len) {
      return true;  // Nothing to do
    }
    if (strncpy_aligned(text_buf, sizeof(text_buf), text, text_len, line_syms,
                        mode)) {
      if (flags & text_render_uppercase) {
        str_toupper_inplace(text_buf);
      }
      BSP_LCD_SetFont((sFONT*)p_font);
      BSP_LCD_SetTextColor(color);
      BSP_LCD_DisplayStringAt((CENTER_MODE == mode) ? 0U : x_pos, y_pos,
                              (uint8_t*)text_buf, mode);
      return true;
    }
  }
  return false;
}

/**
 * Checks if given character is a whitespace
 *
 * @param chr  character to check
 * @return     true if whitespace
 */
static inline bool is_whitespace(int chr) {
  return ' ' == chr || '\t' == chr || '\n' == chr || '\r' == chr;
}

/**
 * Draws a block of text with multiline support
 *
 * @param x_pos      x position
 * @param y_pos      y position
 * @param mode       alignment mode
 * @param p_font     pointer to font used to render the text
 * @param color      text color
 * @param text       test string to render
 * @param flags      text rendering flags
 * @param p_y_final  pointer to variable receiving y position of the last line,
 *                   if not NULL
 * @return           true if successful
 */
static bool draw_text(uint16_t x_pos, uint16_t y_pos, Text_AlignModeTypdef mode,
                      const sFONT* p_font, uint32_t color, const char* text,
                      uint32_t flags, uint16_t* p_y_final) {
  if (p_font && text && y_pos < UINT16_MAX - p_font->Height &&
      y_pos + p_font->Height < LCD_HEIGHT) {
    const char* p_text = text;
    uint16_t curr_y = y_pos;
    while (*p_text != '\0') {
      size_t n_syms = 0U;
      bool res = draw_text_line(x_pos, curr_y, mode, p_font, color, p_text,
                                flags, &n_syms);
      if (p_y_final) {
        *p_y_final = curr_y;
      }
      if (!res || !(flags & text_render_multiline)) {
        return res;
      }
      curr_y += p_font->Height;
      if (curr_y + p_font->Height >= LCD_HEIGHT) {
        return false;
      }
      p_text += n_syms;
      while (*p_text != '\0' && is_whitespace(*p_text)) {
        if('\n' == *p_text) {
          ++p_text;
          break;
        }
        ++p_text;
      }
    }
    return true;
  }
  return false;
}

bool gui_update_progress(const char* caption, const char* operation,
                         uint32_t percent_x100) {
  if (caption && operation) {
    lcd_init_if_needed();
    bool ok = true;

    if (ctx.displayed_page != gui_page_progress) {
      BSP_LCD_SelectLayer(LTDC_ACTIVE_LAYER_BACKGROUND);
      BSP_LCD_SetBackColor(COLOR_BG);
      BSP_LCD_Clear(COLOR_BG);
      ok = ok && draw_text(0, PAGE_CAPTION_Y, CENTER_MODE, PAGE_CAPTION_FONT,
                           COLOR_TEXT, "Firmware Upgrade",
                           text_render_uppercase, NULL);
      ctx.displayed_page = gui_page_progress;
    }

    uint16_t progress_x = (LCD_WIDTH - PROGRESS_WIDTH) / 2U;
    ok = ok && draw_text(progress_x, PROGRESS_CAPTION_Y, LEFT_MODE, &Font20,
                         COLOR_TEXT, operation, 0U, NULL);
    ok = ok && draw_progress_bar(progress_x, PROGRESS_Y, PROGRESS_WIDTH,
                                 PROGRESS_HEIGHT, percent_x100);
    return ok;
  }
  return false;
}

bool gui_show_alert(blsys_alert_type_t type, const char* caption,
                    const char* text, const char* user_action) {
  if ((int)type >= 0 && (int)type < bl_nalerts && caption && text) {
    lcd_init_if_needed();
    if (ctx.displayed_page == gui_page_alert) {
      BSP_LCD_SetLayerVisible(LTDC_ACTIVE_LAYER_BACKGROUND, DISABLE);
    }
    BSP_LCD_SelectLayer(LTDC_ACTIVE_LAYER_FOREGROUND);
    uint32_t bg_color =
        alert_caption_bg[type] ? alert_caption_bg[type] : COLOR_BG;
    BSP_LCD_SetTextColor(bg_color);
    BSP_LCD_FillRect(0U, 0U, LCD_WIDTH, PAGE_CAPTION_HEIGHT);
    BSP_LCD_SetTextColor(COLOR_BG);
    BSP_LCD_FillRect(0U, PAGE_CAPTION_HEIGHT + 1U, LCD_WIDTH,
                     LCD_HEIGHT - PAGE_CAPTION_HEIGHT);

    BSP_LCD_SetBackColor(bg_color);
    bool ok = draw_text(0, PAGE_CAPTION_Y, CENTER_MODE, PAGE_CAPTION_FONT,
                        COLOR_TEXT, caption, text_render_uppercase, NULL);
    BSP_LCD_SetBackColor(COLOR_BG);

    uint16_t y_pos = ALERT_TEXT_Y;
    ok = ok && draw_text(ALERT_TEXT_X, y_pos, LEFT_MODE, &Font20, COLOR_TEXT,
                         text, text_render_multiline, &y_pos);
    if (user_action) {
      ok = ok && draw_text(ALERT_TEXT_X, y_pos + ALERT_ACTION_Y_OFF, LEFT_MODE,
                           &Font20, COLOR_TEXT_LOW, user_action,
                           text_render_multiline, NULL);
    }
    if (ctx.displayed_page != gui_page_alert) {
      BSP_LCD_SetLayerVisible(LTDC_ACTIVE_LAYER_FOREGROUND, ENABLE);
      ctx.displayed_page = gui_page_alert;
    } else {
      BSP_LCD_SetLayerVisible(LTDC_ACTIVE_LAYER_BACKGROUND, ENABLE);
    }
    return ok;
  }
  return false;
}

void gui_hide_alert(void) {
  if (ctx.lcd_initialized && gui_page_alert == ctx.displayed_page) {
    BSP_LCD_SetLayerVisible(LTDC_ACTIVE_LAYER_FOREGROUND, DISABLE);
  }
}
