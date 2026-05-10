#ifndef EVIL_TWIN_H
#define EVIL_TWIN_H

#include <Arduino.h>

void start_evil_twin(int wifi_number);
void stop_evil_twin();
void evil_twin_loop();
bool evil_twin_test_password(const String &password);

// ── WPS PBC sosyal mühendislik saldırısı ────────────────────────────────────
// Portal sayfası kullanıcıya "WPS tuşuna bas" der; arka planda PBC çalışır.
void et_start_wps_pbc();    // WPS Push Button Config başlat
void et_stop_wps_pbc();     // WPS PBC durdur

extern bool   evil_twin_active;
extern String evil_twin_ssid;
extern int    evil_twin_clients;
extern int    evil_twin_channel;
extern uint8_t evil_twin_bssid[6];

// WPS PBC durum değişkenleri (web_interface.cpp okur)
extern bool et_wps_pbc_running;  // PBC aktif mi
extern bool et_wps_pbc_found;    // Şifre yakalandı mı
extern char et_wps_pbc_pass[65]; // Yakalanan şifre

#endif
