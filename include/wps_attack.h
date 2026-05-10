#ifndef WPS_ATTACK_H
#define WPS_ATTACK_H

#include <Arduino.h>

// ─── Ayarlar ──────────────────────────────────────────────────────────────────
#define WPS_MAX_TARGETS          20
#define WPS_PIN_TIMEOUT_MS       5000   // Her PIN denemesi için maks süre (ms)
#define WPS_PIN_TIMEOUT_MIN_MS   1000   // Adaptif timeout alt sınırı
#define WPS_LOCKOUT_THRESHOLD    5      // Ardışık bu kadar hızlı fail → lockout
#define WPS_LOCKOUT_DELAY_MS     30000  // İlk lockout bekleme (ms) — üstel artar
#define WPS_LOCKOUT_DELAY_MAX_MS 180000 // Lockout bekleme üst sınırı (3 dakika)
#define WPS_MAC_ROTATE_EVERY     4      // Her N denemede bir MAC rotasyonu
#define MAX_VENDOR_PINS_PER_VENDOR 30   // Vendor başına maksimum PIN adayı

// ─── Açık seviyesi ─────────────────────────────────────────────────────────────
// Tarama listesinde yıldız olarak gösterilir (kolay lokma tespiti)
enum wps_vuln_t {
  VULN_NONE   = 0,  // Bilinmiyor — tam brute force gerekir
  VULN_LOW    = 1,  // Vendor biliniyor, az PIN algoritması (★)
  VULN_MEDIUM = 2,  // Bilinen algoritma, orta başarı ihtimali (★★)
  VULN_HIGH   = 3,  // Yüksek — Pixie Dust / sabit PIN / seri tabanlı (★★★)
};

// ─── Vendor kimlikleri ─────────────────────────────────────────────────────────
enum wps_vendor_t {
  VENDOR_UNKNOWN = 0,
  // ── ISP modem üreticileri ──────────────────────────────────────────────────
  VENDOR_ZTE,         // TTNET VDSL/Fiber  — ZXHN H108N, H168N, F660
  VENDOR_HUAWEI,      // TTNET Fiber ONT   — HG8245, HG8247, B315, B525
  VENDOR_ZYXEL,       // Superonline/TTNET — VMG, AMG, NBG, P serisi
  VENDOR_TPLINK,      // Her operatör      — TL-WR, Archer, Deco
  VENDOR_SAGEMCOM,    // TTNET Fiber       — F@st 3686, F@st 3890
  VENDOR_ARCADYAN,    // Vodafone TR       — VGV752, VGV7519, Askey
  VENDOR_DLINK,       // Tüketici          — DIR, DWR, DSL serisi
  VENDOR_NETGEAR,     // Tüketici          — R/C/D/Nighthawk serisi
  // ── Router üreticileri ─────────────────────────────────────────────────────
  VENDOR_ASUS,        // Gaming/Ev router  — RT-AC, RT-AX, RT-N, GT serisi
  VENDOR_LINKSYS,     // Ev/SOHO router    — WRT, EA, MR, Velop serisi
  VENDOR_BELKIN,      // Bütçe router      — F7D, F9K, AC serisi
  VENDOR_TENDA,       // Bütçe router      — AC, F, N serisi
  VENDOR_MERCUSYS,    // TP-Link alt marka — MW, MR serisi
  VENDOR_TOTOLINK,    // Çin OEM           — N/A serisi — Realtek chipset, kolay lokma
  // ── Genişletilmiş ISP/OEM ──────────────────────────────────────────────────
  VENDOR_TECHNICOLOR, // Thomson/Technicolor — TG, DGA serisi
  VENDOR_FRITZ,       // AVM Fritz!Box      — 7490, 7590, 6890 serisi
  VENDOR_ARRIS,       // Arris/Motorola     — SBG, TG, CM kablo modemler
  VENDOR_XIAOMI,      // Xiaomi Mi Router   — AX, AC, 4A serisi
  VENDOR_BUFFALO,     // Buffalo            — WHR, WSR, WZR serisi
  VENDOR_MIKROTIK,    // MikroTik           — hAP, RB, Audience serisi
  VENDOR_COMPAL,      // Compal ISP OEM     — CH7465, CH7466 serisi
  VENDOR_SERCOMM,     // Sercomm ISP OEM    — Vodafone/Turkcell branded
  VENDOR_NETIS,       // Netis/Wavlink      — WF, N serisi bütçe router
  VENDOR_CISCO,       // Cisco ISP          — DPC, EPC, ISB kablo serisi
  VENDOR_SAGEM,       // Sagem eski         — F@st 1500, 2604, 3504 serisi
  VENDOR_COMTREND,    // Comtrend ISP       — AR, VR, CT serisi
  VENDOR_ACTIONTEC,   // Actiontec ISP      — GT701, MI424, C1000 serisi
  VENDOR_GEMTEK,      // Gemtek ISP OEM     — Turkcell/TTNet branded
  VENDOR_ISKRATEL,    // Iskratel           — Si2000, Innbox serisi
  VENDOR_DRAYTEK,     // DrayTek            — Vigor serisi, SOHO/ISP
  VENDOR_BILLION,     // Billion Electric   — BiPAC serisi, ISP OEM
  VENDOR_NETCOMM,     // NetComm Wireless   — NF/NL/NTC serisi
  VENDOR_UBIQUITI,    // Ubiquiti           — UniFi/airOS (nadiren WPS'li)
};

struct wps_target_t {
  char         ssid[33];
  uint8_t      bssid[6];
  int          channel;
  int32_t      rssi;
  wps_vendor_t vendor;
  wps_vuln_t   vuln;      // Açık seviyesi — yıldız göstergesi için
};

enum wps_state_t {
  WPS_IDLE,
  WPS_SCANNING,
  WPS_ATTACKING,
  WPS_LOCKED_OUT,
  WPS_SUCCESS,
  WPS_EXHAUSTED,
  WPS_STOPPED,
};

// ─── Dışa açılan değişkenler ──────────────────────────────────────────────────
extern wps_target_t wps_targets[];
extern int          wps_target_count;
extern wps_state_t  wps_attack_state;
extern int          wps_attempt;
extern int          wps_total;
extern char         wps_current_pin[9];
extern char         wps_found_pin[9];
extern char         wps_found_ssid[33];
extern char         wps_found_pass[65];
extern char         wps_vendor_name[32];
extern uint8_t      wps_current_mac[6];
extern int          wps_lockout_count;

// ─── Fonksiyonlar ─────────────────────────────────────────────────────────────
void wps_scan();
void wps_start_attack(int target_index);
void wps_stop();
void wps_loop();

// SSID'den PIN adayları türet (SSID analiz + BSSID ±1 varyantları)
int wps_ssid_to_pins(const char *ssid, const uint8_t *bssid,
                     char pins[][9], int max_pins);

// ─── WPS PBC (Push Button Configuration) durum makinesi ─────────────────────
// Engelsiz (non-blocking) çalışır — main loop'ta her iterasyonda çağrılır.
enum wps_pbc_state_t {
  WPS_PBC_IDLE       = 0,
  WPS_PBC_MONITORING,   // Beacon izleme + PBC probe flood aktif
  WPS_PBC_CONNECTING,   // WPS PBC handshake devam ediyor (buton basıldı tespit edildi)
  WPS_PBC_SUCCESS,      // Şifre başarıyla alındı
  WPS_PBC_FAILED,       // Zaman aşımı veya handshake hatası
};

extern wps_pbc_state_t wps_pbc_attack_state;
extern int             wps_pbc_target_idx;
extern int             wps_pbc_probes_sent;
extern char            wps_pbc_found_ssid[33];
extern char            wps_pbc_found_pass[65];

// wps_pbc_start(): izlemeyi + flood'u başlatır, main loop'ta wps_pbc_loop() çağrılmalı
void wps_pbc_start(int target_idx, uint32_t timeout_ms = 300000);
// wps_pbc_stop(): her durumdan temiz çıkış
void wps_pbc_stop();
// wps_pbc_loop(): main loop'ta her iterasyonda çağrılır (non-blocking)
void wps_pbc_loop();

// ─── Tek seferlik yardımcılar (engelleyici, küçük araçlar) ───────────────────
// wps_pbc_monitor_attack(): blocking versiyon — doğrudan çağrı için
bool wps_pbc_monitor_attack(int target_index, uint32_t timeout_ms = 300000);
// wps_pbc_flood(): art arda N probe gönderir, hızlı
void wps_pbc_flood(int target_index, int count = 50);

#endif
