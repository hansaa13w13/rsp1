#ifndef DEFINITIONS_H
#define DEFINITIONS_H

#define AP_SSID "X"
#define AP_PASS "20192019"
#define SERIAL_DEBUG
#define CHANNEL_MAX 13
#define NUM_FRAMES_PER_DEAUTH 30
#define DEAUTH_BLINK_TIMES 2
#define DEAUTH_BLINK_DURATION 20
#define DEAUTH_TYPE_SINGLE 0
#define DEAUTH_TYPE_ALL 1
#define DEAUTH_TYPE_EVIL_TWIN 2

// Hedef yeniden tarama aralığı (ms)
#define RETRACK_INTERVAL_MS 25000
// CSA beacon gönderim aralığı (ms) — iOS PMF bypass
#define CSA_INTERVAL_MS 500
// Evil Twin şifre testi sırasında sunucu cevap döngüsü (ms)
#define ET_TEST_TIMEOUT_MS 9000
// Proaktif deauth aralığı (ms) — hedef cihazı gerçek AP'den sürekli düşürür
#define ET_DEAUTH_INTERVAL_MS 250

// LED pin tanımları
// ESP32-C3 Super Mini: GPIO 8 (mavi LED)
// Diğer ESP32: GPIO 2 (yerleşik LED)
#if defined(CONFIG_IDF_TARGET_ESP32C3)
  #define LED 8
#else
  #define LED 2
#endif

#ifdef SERIAL_DEBUG
#define DEBUG_PRINT(...)   Serial.print(__VA_ARGS__)
#define DEBUG_PRINTLN(...) Serial.println(__VA_ARGS__)
#define DEBUG_PRINTF(...)  Serial.printf(__VA_ARGS__)
#else
#define DEBUG_PRINT(...)
#define DEBUG_PRINTLN(...)
#define DEBUG_PRINTF(...)
#endif

#ifdef LED
#define BLINK_LED(n, d) blink_led(n, d)
#else
#define BLINK_LED(n, d)
#endif

void blink_led(int num_times, int blink_duration);
void led_on();
void led_off();
void apply_max_performance();
void reapply_wifi_power();

#endif
