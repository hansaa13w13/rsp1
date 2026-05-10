#ifndef WPS_BEACON_IE_H
#define WPS_BEACON_IE_H

#include <Arduino.h>

#define PIXIE_RISK_UNKNOWN  0
#define PIXIE_RISK_LOW      1
#define PIXIE_RISK_MEDIUM   2
#define PIXIE_RISK_HIGH     3

struct wps_device_info_t {
    bool    valid;
    char    manufacturer[64];
    char    model_name[64];
    char    model_number[32];
    char    serial_number[32];
    char    device_name[64];
    bool    ap_setup_locked;
    uint8_t pixie_risk;
    char    pixie_note[80];
    // ── Genişletilmiş WPS IE alanları ──────────────────────────────────────
    uint8_t  wps_version;        // WPS versiyon baytı: 0x10=v1.0, 0x20=v2.0 (0=bilinmiyor)
    uint16_t config_methods;     // Desteklenen yöntemler: 0x0004=PIN, 0x0080=PBC, 0x0100=Display
    bool     selected_registrar; // true = AP şu an PBC bekliyor (Registrar seçili)
    // ── Chipset IE parmak izi (5. tespit yöntemi) ──────────────────────────
    // WPS IE dışındaki vendor-specific IE OUI'larından chipset tespiti.
    // Örn: {0x00,0x17,0x0F}=Ralink, {0x00,0x17,0xF2}=Broadcom
    // Pixie Dust risk değerlendirmesinde ve vendor onayında kullanılır.
    char     chipset_ie_hint[32]; // "Ralink", "Broadcom", "Atheros", vb. (boş=bulunamadı)
};

extern wps_device_info_t wps_device_info;

bool wps_capture_device_info(const uint8_t *bssid, int channel, uint32_t timeout_ms = 3000);
int  wps_serial_to_pins(const char *serial, char pins[][9], int max_pins);
void wps_assess_pixie_risk(wps_device_info_t &info);
uint8_t wps_pin_checksum(uint32_t pin7);

#endif
