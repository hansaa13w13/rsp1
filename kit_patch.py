#!/usr/bin/env python3
"""
Kit-Pro Unlocker v2 — Trial kısıtlamalarını tamamen kaldırır.
Kit-Unlocked.bin flash'a hazır dosya üretir.
"""

import sys

# ── Yardımcı ──────────────────────────────────────────────────────────────────

def load(path):
    with open(path, "rb") as f:
        return bytearray(f.read())

def save(data, path, original_len):
    if len(data) != original_len:
        print(f"  [!] BOYUT HATASI: {len(data)} ≠ {original_len} (fark {len(data)-original_len:+d})")
        print("      Kaydedilmedi.")
        return False
    with open(path, "wb") as f:
        f.write(data)
    print(f"  [✓] Kaydedildi: {path}  ({len(data):,} byte)")
    return True

def replace_all(data, old, new, label, start=0):
    """old'u bul ve new ile değiştir (aynı uzunluk zorunlu). Tüm tekrarları değiştir."""
    assert len(old) == len(new), f"[{label}] Uzunluk uyumsuzluğu: {len(old)} ≠ {len(new)}"
    count = 0
    off = start
    while True:
        pos = data.find(old, off)
        if pos == -1:
            break
        data[pos:pos+len(old)] = new
        count += 1
        off = pos + len(old)
    if count:
        print(f"  [✓] [{label}] {count}x bulunup değiştirildi")
    else:
        print(f"  [!] [{label}] Bulunamadı: {bytes(old[:20]).hex()}...")
    return count

def replace_first(data, old, new, label, start=0):
    """Sadece ilk bulunanı değiştir."""
    assert len(old) == len(new), f"[{label}] Uzunluk uyumsuzluğu: {len(old)} ≠ {len(new)}"
    pos = data.find(old, start)
    if pos == -1:
        print(f"  [!] [{label}] Bulunamadı")
        return False
    data[pos:pos+len(old)] = new
    print(f"  [✓] [{label}] 0x{pos:08X}  {len(old)} byte")
    return True

def pad_to(new_core, target_len, pad_byte=b"\x00"):
    """new_core'u target_len'e kadar pad_byte ile doldur."""
    assert len(new_core) <= target_len, f"Core ({len(new_core)}) > target ({target_len})"
    return new_core + pad_byte * (target_len - len(new_core))

# ── PATCH TANIMLAMALARI ───────────────────────────────────────────────────────

def build_patches():
    patches = []

    # ──────────────────────────────────────────────────────────────────────────
    # PATCH-01: Timer expiry koşulu — asla tetiklenmeyecek hale getir
    # left <= 0  →  left <=-1  (aynı uzunluk: 9 byte)
    # ──────────────────────────────────────────────────────────────────────────
    patches.append(("P01-TIMER-COND", b"left <= 0", b"left <=-1"))

    # ──────────────────────────────────────────────────────────────────────────
    # PATCH-02: Timer countdown gösterim satırı — JS yorumuna çevir
    # 138 byte → 138 byte
    # ──────────────────────────────────────────────────────────────────────────
    p02_old = (
        b"document.getElementById('trial-timer').innerText = 'Trial Time Ends: '"
        b" + Math.floor(left/60) + ':' + (left%60).toString().padStart(2,\"0\");"
    )
    p02_len  = len(p02_old)
    p02_pre  = b"/* trial-timer display removed by unlocker"
    p02_suf  = b"*/"
    p02_new  = p02_pre + b" " * (p02_len - len(p02_pre) - len(p02_suf)) + p02_suf
    assert len(p02_old) == len(p02_new), f"P02: {len(p02_old)} vs {len(p02_new)}"
    patches.append(("P02-TIMER-DISP", p02_old, p02_new))

    # ──────────────────────────────────────────────────────────────────────────
    # PATCH-03: trial-timer div gizle (display:none)
    # 166 byte → 166 byte
    # ──────────────────────────────────────────────────────────────────────────
    p03_old = (
        b'<div style="text-align:center;color:var(--danger);font-size:11px;'
        b'font-weight:bold;margin-top:10px;margin-bottom:15px;'
        b'text-transform:uppercase" id="trial-timer"></div>'
    )
    p03_core = b'<div style="display:none" id="pro-timer"></div>'
    p03_new  = pad_to(p03_core, len(p03_old), b" ")
    assert len(p03_old) == len(p03_new)
    patches.append(("P03-TIMER-DIV", p03_old, p03_new))

    # ──────────────────────────────────────────────────────────────────────────
    # PATCH-04: RESTART butonu aktifleştir (138 byte)
    # Orijinal hex (doğrulanmış):
    # ──────────────────────────────────────────────────────────────────────────
    p04_old = bytes.fromhex(
        "3c627574746f6e20636c6173733d2262746e22207374796c653d22"
        "6f7061636974793a302e353b637572736f723a6e6f742d616c6c6f"
        "77656422206f6e636c69636b3d2263416c65727428275265737461"
        "72742069732064697361626c656420696e20547269616c20766572"
        "73696f6e2e2729223e5245535441525420f09f94923c2f627574746f6e3e"
    )
    p04_core = b'<button class="btn" onclick="api(\'/restart\')">RESTART</button>'
    p04_new  = pad_to(p04_core, len(p04_old))
    assert len(p04_old) == len(p04_new), f"{len(p04_old)} vs {len(p04_new)}"
    patches.append(("P04-RESTART-BTN", p04_old, p04_new))

    # ──────────────────────────────────────────────────────────────────────────
    # PATCH-05: EVIL-TWIN butonu aktifleştir (169 byte)
    # ──────────────────────────────────────────────────────────────────────────
    p05_old = bytes.fromhex(
        "3c627574746f6e20636c6173733d2262746e22207374796c653d22"
        "626f726465722d636f6c6f723a766172282d2d64616e676572293b"
        "6f7061636974793a302e353b637572736f723a6e6f742d616c6c6f"
        "77656422206f6e636c69636b3d2263416c65727428274576696c2d"
        "5477696e2069732064697361626c656420696e20547269616c2076"
        "657273696f6e2e2729223e4556494c2d5457494e20f09f94923c2f"
        "627574746f6e3e"
    )
    p05_core = b'<button class="btn" style="border-color:var(--danger)" onclick="startEvilTwin()">EVIL-TWIN</button>'
    p05_new  = pad_to(p05_core, len(p05_old))
    assert len(p05_old) == len(p05_new), f"{len(p05_old)} vs {len(p05_new)}"
    patches.append(("P05-EVILTWIN-BTN", p05_old, p05_new))

    # ──────────────────────────────────────────────────────────────────────────
    # PATCH-06: Başlıkları güncelle
    # ──────────────────────────────────────────────────────────────────────────
    patches.append(("P06-TITLE-H1",   b"PENTEST KIT TRIAL",           b"PENTEST KIT  PRO "))
    patches.append(("P07-TITLE-HTML", b"WiFi Pentest Kit TRIAL V1.0", b"WiFi Pentest Kit  PRO  V1.0"))

    # ──────────────────────────────────────────────────────────────────────────
    # PATCH-07: "TRIAL EXPIRED" → "BOOT COMPLETE" (13 byte)
    # ──────────────────────────────────────────────────────────────────────────
    patches.append(("P08-TRIAL-EXP-UP",  b"TRIAL EXPIRED", b"BOOT COMPLETE"))
    patches.append(("P09-TRIAL-EXP-LOW", b"Trial Expired",  b"Boot Complete"))

    # ──────────────────────────────────────────────────────────────────────────
    # PATCH-08: BUY PREMIUM → ALL ENABLED (11 byte)
    # ──────────────────────────────────────────────────────────────────────────
    patches.append(("P10-BUY-PREM", b"BUY PREMIUM", b"ALL ENABLED"))

    # ──────────────────────────────────────────────────────────────────────────
    # PATCH-09: github.com/mehedishakeel → kaldır (aynı uzunluk)
    # ──────────────────────────────────────────────────────────────────────────
    old_url = b"http://github.com/mehedishakeel"
    new_url = b"http://192.168.1.1/admin       "
    patches.append(("P11-URL", old_url, new_url))

    # ──────────────────────────────────────────────────────────────────────────
    # PATCH-10: Diğer trial stringleri
    # ──────────────────────────────────────────────────────────────────────────
    patches.append(("P12-FEAT-STR", b"Feature disabled in Trial", b"Feature enabled, PRO only"))
    patches.append(("P13-ET-STR",   b"Evil-Twin disabled in Trial", b"Evil-Twin enabled, PRO only"))

    # trial HTML sayfasindaki "Please restart the board" metni
    old_msg = b"Please restart the board physically to try again."
    new_msg = b"Device is in PRO mode. All features are active.  "
    patches.append(("P14-RESTART-MSG", old_msg, new_msg))

    # Gelistirici sosyal medya etiketi (14 byte)
    patches.append(("P15-DEV-HANDLE", b"@mehedishakeel", b"@PentestKitPro"))

    return patches

# ── ANA İŞLEM ────────────────────────────────────────────────────────────────

def main():
    src  = "Kit-Trial.bin"
    dest = "Kit-Unlocked.bin"

    print("=" * 64)
    print("  KIT-PRO UNLOCKER v2 — Trial Kısıtlamaları Kaldırılıyor")
    print("=" * 64)

    print(f"\n[*] Yükleniyor: {src}")
    data = load(src)
    original_len = len(data)
    print(f"    Boyut: {original_len:,} byte")

    patches = build_patches()

    print(f"\n[*] {len(patches)} patch uygulanıyor...\n")
    for label, old, new in patches:
        replace_all(data, bytearray(old), bytearray(new), label)

    # ── Boyut doğrulaması
    print(f"\n── Boyut doğrulama ──────────────────────────────────────────")
    if len(data) == original_len:
        print(f"  [✓] Boyut korundu: {len(data):,} byte")
    else:
        print(f"  [!] BOYUT DEĞİŞTİ: {original_len:,} → {len(data):,} ({len(data)-original_len:+d})")

    # ── Kısıtlama tarama
    print(f"\n── Kısıtlama taraması ───────────────────────────────────────")
    checks = [
        (b"disabled in Trial",         "Devre dışı bırakma"),
        (b"left <= 0",                  "Timer koşulu"),
        (b"Trial Time Ends",            "Timer gösterimi"),
        (b"TRIAL EXPIRED",              "Trial süresi doldu (büyük)"),
        (b"Trial Expired",              "Trial süresi doldu (küçük)"),
        (b"BUY PREMIUM",               "Satın al linki"),
        (b"mehedishakeel",              "Geliştirici linki"),
        (b"PENTEST KIT TRIAL",          "Trial başlığı"),
        (b"WiFi Pentest Kit TRIAL",     "Trial HTML başlığı"),
        (b"Feature disabled in Trial",  "Locked feature msg"),
        (b"Evil-Twin disabled in Trial", "Evil-Twin locked msg"),
    ]

    # Son kontrolü farklı işle (bytes tuple değil string)
    all_ok = True
    for item in checks:
        pat, name = item[0], item[1] if isinstance(item[1], str) else item[1].decode()
        pos = bytes(data).find(pat)
        if pos != -1:
            ctx = bytes(data[max(0,pos-15):pos+len(pat)+25])
            txt = "".join(chr(b) if 32<=b<127 else "." for b in ctx)
            print(f"  [!] Hâlâ var: '{name}' @ 0x{pos:08X} — {txt.strip()!r}")
            all_ok = False
        else:
            print(f"  [✓] Temizlendi: '{name}'")

    # ── Kaydet
    print(f"\n── Kayıt ─────────────────────────────────────────────────")
    ok = save(data, dest, original_len)

    print(f"\n{'='*64}")
    if ok and all_ok:
        print("  ✓ BAŞARILI — Kit-Unlocked.bin flash'a hazır!")
        print(f"  Dosya: {dest}")
    elif ok:
        print("  ~ TAMAMLANDI — bazı uyarılar var (yukarıya bakın).")
        print(f"  Dosya: {dest}")
    else:
        print("  ✗ HATA — dosya kaydedilemedi.")
    print("=" * 64)

if __name__ == "__main__":
    main()
