#ifndef WEB_INTERFACE_H
#define WEB_INTERFACE_H

void start_web_interface();
void web_interface_handle_client();

// Evil Twin şifre testi durumu — main.cpp'den erişilir
extern bool   et_test_pending;
extern bool   et_result_ready;
extern bool   et_result_correct;
extern String et_tested_ssid;
extern String et_tested_password;

// WPS ertelenmiş işlemler — main loop'tan çalıştırılır
// Handler anında redirect gönderir, WiFi bozan işlem main loop'ta yapılır
extern bool wps_scan_pending;
extern bool wps_attack_pending;
extern int  wps_attack_pending_idx;

// WPS PBC ertelenmiş işlemler
extern bool wps_pbc_monitor_pending;  // PBC izleme+bağlantı başlat
extern bool wps_pbc_flood_pending;    // PBC flood başlat
extern int  wps_pbc_pending_idx;      // Hedef indeksi (her iki mod için)

// Evil Twin ertelenmiş başlatma — handler redirect gönderir, main loop başlatır
extern bool et_start_pending;
extern int  et_start_wifi_number;

// Ağ yeniden tarama — handler redirect gönderir, main loop taramayı yapar
extern bool rescan_pending;
void web_interface_do_rescan();

#endif
