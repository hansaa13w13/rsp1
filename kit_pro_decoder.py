#!/usr/bin/env python3
"""
Kit-Pro.bin — Tam Decoder / Editor / Encoder
WiFi Pentest Kit firmware binary dosyasını decode eder,
insan okunabilir formata çevirir, düzenler ve tekrar bin'e yazar.
"""

import struct, re, os, sys, json, shutil
from datetime import datetime
from pathlib import Path

# ── Bölüm sınırları (analiz sonucu tespit edildi) ─────────────────────────────
SECTIONS = [
    {"name": "HEADER",        "start": 0x000000, "end": 0x00000C},
    {"name": "VECTOR_TABLE",  "start": 0x00000C, "end": 0x000020},
    {"name": "CODE_KM4",      "start": 0x000020, "end": 0x079B88},
    {"name": "WEB_INTERFACE", "start": 0x079B88, "end": 0x082000},
    {"name": "STRINGS_DATA",  "start": 0x082000, "end": 0x09A000},
    {"name": "WIFI_FW",       "start": 0x09A000, "end": 0x0C4000},
]

# ── Dosya yükle ───────────────────────────────────────────────────────────────

def load_bin(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()

# ── Header parse ──────────────────────────────────────────────────────────────

def parse_header(data: bytes) -> dict:
    magic   = data[0:8].decode("ascii", errors="replace")
    b8      = data[8]
    b9      = data[9]
    b10     = data[10]
    b11     = data[11]
    size_le = struct.unpack_from("<H", data, 9)[0]
    return {
        "magic":   magic,
        "byte_8":  f"0x{b8:02X}",
        "byte_9":  f"0x{b9:02X} ({b9})",
        "byte_10": f"0x{b10:02X} ({b10})",
        "byte_11": f"0x{b11:02X} ({b11})",
        "size_hint_le16": size_le,
        "raw_hex": data[0:12].hex(),
    }

# ── HTML sayfalarını çıkar ────────────────────────────────────────────────────

def extract_html_pages(data: bytes) -> list[dict]:
    pages = []
    pattern = re.compile(b"<!DOCTYPE html>.*?</html>", re.DOTALL | re.IGNORECASE)
    for m in pattern.finditer(data):
        pages.append({
            "offset": m.start(),
            "size":   len(m.group()),
            "content": m.group().decode("utf-8", errors="replace"),
        })
    return pages

# ── Anlamlı stringleri çıkar ──────────────────────────────────────────────────

def extract_strings(data: bytes, min_len: int = 6) -> list[dict]:
    results = []
    pattern = re.compile(b"[\x20-\x7E]{" + str(min_len).encode() + b",}")
    for m in pattern.finditer(data):
        s      = m.group().decode("ascii")
        letters = sum(c.isalpha() for c in s)
        # Sadece gerçekten okunabilir olanlar (ARM opcode false positive değil)
        if letters >= 4 or (letters >= 2 and " " in s):
            results.append({"offset": m.start(), "text": s})
    return results

# ── HTTP route'larını çıkar ───────────────────────────────────────────────────

def extract_routes(data: bytes) -> list[dict]:
    routes = []
    pattern = re.compile(b"(/[a-zA-Z_][a-zA-Z0-9_/]*)")
    for m in pattern.finditer(data):
        r = m.group().decode("ascii")
        if len(r) >= 4:
            routes.append({"offset": m.start(), "route": r})
    return routes

# ── Evil-Twin / saldırı içeriklerini çıkar ───────────────────────────────────

def extract_attack_strings(data: bytes) -> list[dict]:
    keywords = [
        b"EVIL-TWIN", b"Phishing", b"Captured", b"deauth", b"beacon",
        b"handshake", b"Evil-Twin", b"password", b"Password", b"credential",
        b"OTA", b"eviltwi", b"DDOS", b"ddos", b"spam", b"Spam",
        b"WiFi Pentest", b"Kit", b"ATTACK", b"Attack"
    ]
    found = []
    for kw in keywords:
        idx = 0
        while True:
            pos = data.find(kw, idx)
            if pos == -1:
                break
            # Bağlamla birlikte al (64 byte)
            ctx_start = max(0, pos - 10)
            ctx_end   = min(len(data), pos + 64)
            ctx = data[ctx_start:ctx_end]
            printable = ctx.decode("ascii", errors="replace")
            printable = "".join(c if 32 <= ord(c) < 127 else "." for c in printable)
            found.append({
                "offset":  pos,
                "keyword": kw.decode("ascii", errors="replace"),
                "context": printable.strip(),
            })
            idx = pos + 1
    return found

# ── Konfigürasyon verilerini çıkar ────────────────────────────────────────────

def extract_config(data: bytes) -> dict:
    cfg = {}
    # JSON fragmanları
    json_hits = []
    pattern = re.compile(b'\{"[a-zA-Z_]')
    for m in pattern.finditer(data):
        end = min(m.start() + 200, len(data))
        frag = data[m.start():end]
        text = frag.decode("ascii", errors="replace")
        text = text[:text.find("\x00")] if "\x00" in text else text
        json_hits.append({"offset": m.start(), "fragment": text.strip()})
    cfg["json_fragments"] = json_hits

    # API endpoint'leri
    routes_raw = re.findall(b"(/[a-zA-Z_][a-zA-Z0-9_]{2,})", data)
    cfg["api_endpoints"] = sorted(set(r.decode() for r in routes_raw if len(r) >= 4))

    # IP adresleri
    ip_pattern = re.compile(b"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
    cfg["ip_addresses"] = list(set(m.group().decode() for m in ip_pattern.finditer(data)))

    # WiFi/ağ ilgili stringler
    wifi_strings = []
    wifi_kw = [b"ssid", b"SSID", b"password", b"bssid", b"channel", b"WPA", b"WPS",
               b"AP_", b"STA_", b"softap", b"SoftAP"]
    for kw in wifi_kw:
        idx = 0
        while True:
            pos = data.find(kw, idx)
            if pos == -1:
                break
            ctx = data[max(0,pos-5):min(len(data),pos+40)]
            txt = "".join(chr(b) if 32<=b<127 else "." for b in ctx)
            wifi_strings.append({"offset": pos, "text": txt.strip()})
            idx = pos + 1
    cfg["wifi_strings"] = wifi_strings[:50]

    return cfg

# ── Hex dump (belirli aralık) ─────────────────────────────────────────────────

def hex_dump(data: bytes, start_offset: int = 0, width: int = 16) -> str:
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        addr  = start_offset + i
        hex_p = " ".join(f"{b:02x}" for b in chunk)
        asc_p = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{addr:08x}:  {hex_p:<{width*3}}  {asc_p}")
    return "\n".join(lines)

# ── Tüm decoded içeriği dosyaya yaz ──────────────────────────────────────────

def decode_to_file(bin_path: str, out_path: str) -> None:
    print(f"[*] Yükleniyor: {bin_path}")
    data = load_bin(bin_path)

    lines = []
    W = lambda *args: lines.append(" ".join(str(a) for a in args))
    SEP = lambda c="=": W(c * 72)

    SEP("="); W("  KIT-PRO BIN — TAM DECODE RAPORU")
    W(f"  Dosya   : {bin_path}")
    W(f"  Boyut   : {len(data):,} byte  ({len(data)/1024:.1f} KB)")
    W(f"  Tarih   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    SEP("="); W("")

    # 1. Header
    SEP(); W("  [1] HEADER"); SEP()
    hdr = parse_header(data)
    for k, v in hdr.items():
        W(f"  {k:<20}: {v}")
    W("")

    # 2. Bölüm haritası
    SEP(); W("  [2] BÖLÜM HARİTASI"); SEP()
    for s in SECTIONS:
        size = s["end"] - s["start"]
        W(f"  {s['name']:<20}: 0x{s['start']:08X} - 0x{s['end']:08X}  ({size:,} byte)")
    W("")

    # 3. Header hex dump
    SEP(); W("  [3] HEADER HEX DUMP (ilk 64 byte)"); SEP()
    W(hex_dump(data[:64]))
    W("")

    # 4. HTML sayfaları
    SEP(); W("  [4] GÖMÜLÜ HTML SAYFALAR (Phishing / Web Arayüz)"); SEP()
    html_pages = extract_html_pages(data)
    W(f"  Toplam {len(html_pages)} HTML sayfa bulundu.")
    W("")
    for i, page in enumerate(html_pages, 1):
        W(f"  ── HTML Sayfa #{i} ──")
        W(f"  Offset : 0x{page['offset']:08X}")
        W(f"  Boyut  : {page['size']:,} byte")
        W(f"  İçerik :")
        # Güzelleştir
        content = page["content"]
        for line in content.split(">"):
            line = line.strip()
            if line:
                W(f"    {line}>")
        W("")

    # 5. Saldırı stringleri
    SEP(); W("  [5] SALDIRI / EVIL-TWIN İÇERİĞİ"); SEP()
    attacks = extract_attack_strings(data)
    seen = set()
    for a in attacks:
        key = a["context"][:40]
        if key not in seen:
            seen.add(key)
            W(f"  [0x{a['offset']:08X}] <{a['keyword']}> {a['context']!r}")
    W("")

    # 6. API endpoint'ler
    SEP(); W("  [6] HTTP API ENDPOINT'LERİ"); SEP()
    cfg = extract_config(data)
    for ep in sorted(set(cfg["api_endpoints"])):
        W(f"  {ep}")
    W("")

    # 7. IP adresleri
    SEP(); W("  [7] IP ADRESLERİ"); SEP()
    for ip in sorted(cfg["ip_addresses"]):
        W(f"  {ip}")
    W("")

    # 8. JSON fragmanları
    SEP(); W("  [8] JSON / KONFİGÜRASYON FRAGMENTLARI"); SEP()
    for jf in cfg["json_fragments"]:
        W(f"  [0x{jf['offset']:08X}] {jf['fragment']!r}")
    W("")

    # 9. WiFi stringleri
    SEP(); W("  [9] WiFi / AĞ İLGİLİ STRİNGLER"); SEP()
    seen_wifi = set()
    for ws in cfg["wifi_strings"]:
        key = ws["text"][:30]
        if key not in seen_wifi:
            seen_wifi.add(key)
            W(f"  [0x{ws['offset']:08X}] {ws['text']!r}")
    W("")

    # 10. Tüm anlamlı stringler
    SEP(); W("  [10] TÜM ANLAMLI STRİNGLER"); SEP()
    all_strings = extract_strings(data, min_len=8)
    W(f"  Toplam {len(all_strings)} anlamlı string bulundu.")
    W("")
    seen_str = set()
    for s in all_strings:
        txt = s["text"]
        if len(txt) >= 8 and sum(c.isalpha() for c in txt) >= 4:
            if txt not in seen_str:
                seen_str.add(txt)
                W(f"  [0x{s['offset']:08X}] {txt!r}")
    W("")

    # 11. Kod bölümü hex dump (ilk 512 byte)
    SEP(); W("  [11] KOD BÖLÜMÜ HEX DUMP (0x20 - 0x220)"); SEP()
    W(hex_dump(data[0x20:0x220], start_offset=0x20))
    W("")

    # 12. Web arayüzü bölümü hex dump
    SEP(); W("  [12] WEB ARAYÜZÜ BAŞLANGICI (0x79B88)"); SEP()
    W(hex_dump(data[0x79B88:0x79C88], start_offset=0x79B88))
    W("")

    # Yaz
    output = "\n".join(lines)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(output)

    print(f"[✓] Decode tamamlandı: {out_path}")
    print(f"    {len(lines)} satır, {len(output):,} karakter")

# ── HTML sayfalarını ayrı dosyalara çıkar ─────────────────────────────────────

def extract_html_files(bin_path: str, out_dir: str) -> None:
    data = load_bin(bin_path)
    os.makedirs(out_dir, exist_ok=True)
    pages = extract_html_pages(data)
    print(f"[*] {len(pages)} HTML sayfa bulundu.")
    for i, page in enumerate(pages, 1):
        fname = os.path.join(out_dir, f"page_{i:02d}_0x{page['offset']:08X}.html")
        with open(fname, "w", encoding="utf-8") as f:
            f.write(page["content"])
        print(f"  [✓] {fname}  ({page['size']:,} byte)")

# ── Patch + kaydet ────────────────────────────────────────────────────────────

def patch_bytes(data: bytes, offset: int, new_bytes: bytes) -> bytes:
    if offset + len(new_bytes) > len(data):
        raise ValueError(f"Offset aralık dışı: {offset} + {len(new_bytes)} > {len(data)}")
    ba = bytearray(data)
    ba[offset:offset+len(new_bytes)] = new_bytes
    print(f"[✓] Patch: {len(new_bytes)} byte @ 0x{offset:08X}")
    return bytes(ba)

def save_bin(data: bytes, path: str, backup: bool = True) -> None:
    if backup and os.path.isfile(path):
        ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
        bak = f"{path}.{ts}.bak"
        shutil.copy2(path, bak)
        print(f"[i] Yedek: {bak}")
    with open(path, "wb") as f:
        f.write(data)
    print(f"[✓] Kaydedildi: {path}  ({len(data):,} byte)")

# ── İnteraktif menü ───────────────────────────────────────────────────────────

def menu(bin_path: str) -> None:
    data = load_bin(bin_path)

    MENU = """
┌────────────────────────────────────────────────────────────────────┐
│                   KIT-PRO BIN DECODER / EDITOR                     │
├──────┬─────────────────────────────────────────────────────────────┤
│  1   │ Tam decode → rapor.txt olarak kaydet                        │
│  2   │ HTML sayfalarını ayrı dosyalara çıkar                       │
│  3   │ Saldırı içeriklerini göster (Evil-Twin, deauth, vb.)        │
│  4   │ API endpoint'lerini göster                                   │
│  5   │ Tüm stringleri göster                                        │
│  6   │ Hex dump (offset ve uzunluk seç)                            │
│  7   │ Pattern / string ara                                         │
│  8   │ Byte/string patch (düzenleme)                                │
│  9   │ Kaydet (orijinal veya yeni dosya)                            │
│  0   │ Çıkış                                                       │
└──────┴─────────────────────────────────────────────────────────────┘"""

    while True:
        print(MENU)
        print(f"  [Yüklü: {bin_path}  {len(data):,} byte]")
        ch = input("\nSeçim: ").strip()

        if ch == "0":
            print("Çıkış.")
            break

        elif ch == "1":
            out = input("  Çıktı dosyası [Kit-Pro_decoded.txt]: ").strip() or "Kit-Pro_decoded.txt"
            decode_to_file(bin_path, out)

        elif ch == "2":
            out = input("  Klasör adı [html_pages]: ").strip() or "html_pages"
            extract_html_files(bin_path, out)

        elif ch == "3":
            attacks = extract_attack_strings(data)
            seen = set()
            for a in attacks:
                key = a["context"][:40]
                if key not in seen:
                    seen.add(key)
                    print(f"  [0x{a['offset']:08X}] {a['keyword']!r:15} {a['context']!r}")

        elif ch == "4":
            cfg = extract_config(data)
            for ep in sorted(set(cfg["api_endpoints"])):
                print(f"  {ep}")

        elif ch == "5":
            strings = extract_strings(data, 8)
            seen = set()
            for s in strings:
                if s["text"] not in seen and sum(c.isalpha() for c in s["text"]) >= 4:
                    seen.add(s["text"])
                    print(f"  [0x{s['offset']:08X}] {s['text']!r}")

        elif ch == "6":
            try:
                off = int(input("  Offset (hex/dec, ör: 0x82000): "), 0)
                lng = int(input("  Uzunluk [256]: ") or "256")
                print(hex_dump(data[off:off+lng], start_offset=off))
            except Exception as e:
                print(f"  [!] {e}")

        elif ch == "7":
            mode = input("  [h]ex / [s]tring? ").strip().lower()
            try:
                if mode == "h":
                    pat = bytes.fromhex(input("  Hex: ").replace(" ", ""))
                else:
                    pat = input("  String: ").encode()
                idx, results = 0, []
                while True:
                    pos = data.find(pat, idx)
                    if pos == -1: break
                    results.append(pos)
                    idx = pos + 1
                if results:
                    print(f"  {len(results)} adet:")
                    for p in results[:30]:
                        ctx = data[p:p+40].decode("ascii", errors="replace")
                        ctx = "".join(c if 32<=ord(c)<127 else "." for c in ctx)
                        print(f"    0x{p:08X}: {ctx!r}")
                else:
                    print("  Bulunamadı.")
            except Exception as e:
                print(f"  [!] {e}")

        elif ch == "8":
            try:
                off    = int(input("  Offset (hex/dec): "), 0)
                mode   = input("  [h]ex string / [s]tring metin? ").strip().lower()
                if mode == "h":
                    nb = bytes.fromhex(input("  Hex (ör: DEADBEEF): ").replace(" ", ""))
                else:
                    nb = input("  Yeni metin: ").encode("utf-8")
                print(f"  Mevcut: {data[off:off+len(nb)].hex()}")
                print(f"  Yeni  : {nb.hex()}")
                confirm = input("  Uygulansın mı? (e/H): ").strip().lower()
                if confirm == "e":
                    data = patch_bytes(data, off, nb)
            except Exception as e:
                print(f"  [!] {e}")

        elif ch == "9":
            out    = input(f"  Kayıt yolu [{bin_path}]: ").strip() or bin_path
            backup = input("  Yedek al? (E/h): ").strip().lower() not in ("h", "n")
            try:
                save_bin(data, out, backup=backup)
            except Exception as e:
                print(f"  [!] {e}")

        else:
            print("  Geçersiz seçim.")

# ── Giriş noktası ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    bin_path = sys.argv[1] if len(sys.argv) > 1 else "Kit-Pro.bin"

    if not os.path.isfile(bin_path):
        print(f"[!] Dosya bulunamadı: {bin_path}")
        sys.exit(1)

    # --decode argümanıyla direkt rapor üret
    if len(sys.argv) > 2 and sys.argv[2] == "--decode":
        out = sys.argv[3] if len(sys.argv) > 3 else "Kit-Pro_decoded.txt"
        decode_to_file(bin_path, out)
        # HTML sayfalarını da çıkar
        extract_html_files(bin_path, "html_pages")
    else:
        menu(bin_path)
