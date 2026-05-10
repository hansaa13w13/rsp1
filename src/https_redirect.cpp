#include "https_redirect.h"
#include <esp_https_server.h>

// ─── Self-signed EC P-256 sertifika (100 yıl geçerli — 2026–2126) ───────────
// Captive portal için üretilmiştir. Süre dolma hatası HİÇBİR ZAMAN oluşmaz.
//
// ⚠ TARAYICI UYARISI HAKKINDA:
// "Güvenilmeyen sertifika" uyarısı sertifikanın süresiyle ilgili DEĞİLDİR.
// Uyarının sebebi: tarayıcılar yalnızca DigiCert, Let's Encrypt gibi ~150
// onaylı CA (Sertifika Otoritesi) imzalı sertifikalara güvenir. Özel IP
// (192.168.4.1) için hiçbir gerçek CA sertifika vermez — bu X.509 PKI
// mimarisinin değiştirilemez bir sınırıdır. Kod değişikliğiyle aşılamaz.
// Pratik çözüm: kurban cihazına kök CA sertifikası kurulursa uyarı kalkar
// (sosyal mühendislik / MDM profili).
static const uint8_t HTTPS_CERT_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBiTCCAS+gAwIBAgIUBxITQakSNQAT0cAFIeaG8TQGvk8wCgYIKoZIzj0EAwIw\n"
    "GTEXMBUGA1UEAwwOY2FwdGl2ZS5wb3J0YWwwIBcNMjYwNTEwMTAwNDA3WhgPMjEy\n"
    "NjA0MTYxMDA0MDdaMBkxFzAVBgNVBAMMDmNhcHRpdmUucG9ydGFsMFkwEwYHKoZI\n"
    "zj0CAQYIKoZIzj0DAQcDQgAEvxQaztka/hQ4C7oGvAtvW1Y8EB7jOzE1vjm/IDo3\n"
    "Ov55DyoYbVD07O0ujS7rw+XkwqA2ZVgx8Dqf/Fmz6LSDoaNTMFEwHQYDVR0OBBYE\n"
    "FJMCavXWnKwQTpHOl385IkjwARxAMB8GA1UdIwQYMBaAFJMCavXWnKwQTpHOl385\n"
    "IkjwARxAMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIgd5YeNUpc\n"
    "69TK09bzM6CVQjsijV/B2q5x5XEouU8sIK8CIQCGPfmYkm6NtKex4em+MqN0Q4W6\n"
    "fCfDiaUvWrEV9LuoBw==\n"
    "-----END CERTIFICATE-----\n";

static const uint8_t HTTPS_KEY_PEM[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQghjENMaBI0XSBFdRZ\n"
    "gTjS0cGinRpxAAAyTgLSaGlnkxOhRANCAAS/FBrO2Rr+FDgLuga8C29bVjwQHuM7\n"
    "MTW+Ob8gOjc6/nkPKhhtUPTs7S6NLuvD5eTCoDZlWDHwOp/8WbPotIOh\n"
    "-----END PRIVATE KEY-----\n";

static httpd_handle_t s_https_server = NULL;

// ─── Yönlendirme işleyici — GET, POST, HEAD ───────────────────────────────────
// Gelen her HTTPS isteğini HTTP captive portal'ına yönlendirir.
static esp_err_t redirect_handler(httpd_req_t *req) {
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", "http://192.168.4.1/");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
}

static const httpd_uri_t uri_get = {
    .uri      = "*",
    .method   = HTTP_GET,
    .handler  = redirect_handler,
    .user_ctx = NULL,
};

static const httpd_uri_t uri_post = {
    .uri      = "*",
    .method   = HTTP_POST,
    .handler  = redirect_handler,
    .user_ctx = NULL,
};

static const httpd_uri_t uri_head = {
    .uri      = "*",
    .method   = HTTP_HEAD,
    .handler  = redirect_handler,
    .user_ctx = NULL,
};

// ─── HTTPS sunucusunu başlat ──────────────────────────────────────────────────
void https_redirect_start() {
    if (s_https_server) return;

    httpd_ssl_config_t cfg = HTTPD_SSL_CONFIG_DEFAULT();

    // Sertifika ve özel anahtar
    cfg.cacert_pem  = HTTPS_CERT_PEM;
    cfg.cacert_len  = sizeof(HTTPS_CERT_PEM);
    cfg.prvtkey_pem = HTTPS_KEY_PEM;
    cfg.prvtkey_len = sizeof(HTTPS_KEY_PEM);

    // Bellek tasarrufu: maksimum 2 eş zamanlı TLS bağlantısı (~40 KB/bağlantı)
    cfg.httpd.max_open_sockets  = 2;
    cfg.httpd.stack_size        = 8192;
    cfg.httpd.max_uri_handlers  = 4;
    cfg.httpd.ctrl_port         = 32769;  // port 80 sunucusuyla çakışmasın
    cfg.httpd.lru_purge_enable  = true;   // Eski bağlantıları otomatik temizle
    cfg.httpd.uri_match_fn      = httpd_uri_match_wildcard;

    if (httpd_ssl_start(&s_https_server, &cfg) != ESP_OK) {
        s_https_server = NULL;
        return;
    }

    httpd_register_uri_handler(s_https_server, &uri_get);
    httpd_register_uri_handler(s_https_server, &uri_post);
    httpd_register_uri_handler(s_https_server, &uri_head);
}

// ─── HTTPS sunucusunu durdur ──────────────────────────────────────────────────
void https_redirect_stop() {
    if (!s_https_server) return;
    httpd_ssl_stop(s_https_server);
    s_https_server = NULL;
}
