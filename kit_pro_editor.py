#!/usr/bin/env python3
"""
Kit-Pro.bin Decoder / Editor / Encoder
ARM firmware binary dosyasını decode eder, düzenler ve tekrar bin haline getirir.
"""

import struct
import os
import sys
import shutil
from datetime import datetime


# ─────────────────────────────────────────────────────────────
# HEADER TANIMI
# ─────────────────────────────────────────────────────────────
HEADER_SIZE   = 12          # ilk 12 byte header kabul edildi
MAGIC_OFFSET  = 0           # 8 byte ASCII kimlik
SIZE_OFFSET   = 8           # 4 byte (uint32 LE) — veri büyüklüğü ipucu
FF_FILL       = 0xFF        # dolgu baytı (flash erase değeri)


# ─────────────────────────────────────────────────────────────
# YARDIMCI FONKSİYONLAR
# ─────────────────────────────────────────────────────────────

def hex_dump(data: bytes, start_offset: int = 0, width: int = 16) -> str:
    """Verilen byte dizisini hex+ASCII dump olarak döndürür."""
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        addr  = start_offset + i
        hex_p = " ".join(f"{b:02x}" for b in chunk)
        asc_p = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{addr:08x}:  {hex_p:<{width*3}}  {asc_p}")
    return "\n".join(lines)


def checksum_simple(data: bytes) -> int:
    """Basit toplam checksum (mod 256)."""
    return sum(data) & 0xFF


def checksum_xor(data: bytes) -> int:
    """XOR checksum."""
    result = 0
    for b in data:
        result ^= b
    return result


def checksum_crc32(data: bytes) -> int:
    """CRC-32 hesapla."""
    import binascii
    return binascii.crc32(data) & 0xFFFFFFFF


# ─────────────────────────────────────────────────────────────
# DECODE  (BIN → Python nesnesi)
# ─────────────────────────────────────────────────────────────

class KitProBin:
    """Kit-Pro .bin dosyasını temsil eden sınıf."""

    def __init__(self):
        self.raw: bytes        = b""
        self.magic: str        = ""
        self.header: bytes     = b""
        self.payload: bytes    = b""
        self.file_path: str    = ""
        self.file_size: int    = 0

    # ── yükleme ──────────────────────────────────────────────

    def load(self, path: str) -> None:
        """BIN dosyasını yükle ve ayrıştır."""
        if not os.path.isfile(path):
            raise FileNotFoundError(f"Dosya bulunamadı: {path}")

        with open(path, "rb") as f:
            self.raw = f.read()

        self.file_path = path
        self.file_size = len(self.raw)
        self._parse()

    def _parse(self) -> None:
        """Header ve payload'ı ayrıştır."""
        if len(self.raw) < HEADER_SIZE:
            raise ValueError("Dosya çok küçük, geçerli bir Kit-Pro.bin değil.")

        self.header  = self.raw[:HEADER_SIZE]
        self.magic   = self.raw[MAGIC_OFFSET:MAGIC_OFFSET+8].decode("ascii", errors="replace")
        self.payload = self.raw[HEADER_SIZE:]

    # ── bilgi gösterimi ──────────────────────────────────────

    def info(self) -> str:
        """Dosya hakkında özet bilgi."""
        non_ff = sum(1 for b in self.raw if b != 0xFF)
        non_00 = sum(1 for b in self.raw if b != 0x00)
        used   = sum(1 for b in self.raw if b not in (0x00, 0xFF))

        lines = [
            "=" * 60,
            "  KIT-PRO BIN DOSYASI BİLGİLERİ",
            "=" * 60,
            f"  Dosya       : {self.file_path}",
            f"  Boyut       : {self.file_size:,} byte  ({self.file_size/1024:.1f} KB)",
            f"  Magic/ID    : {self.magic!r}",
            f"  Header      : {self.header.hex()}",
            f"  Payload     : {len(self.payload):,} byte",
            "",
            "  ── Byte İstatistikleri ──",
            f"  0xFF dolu   : {self.file_size - non_ff:,} byte",
            f"  0x00 dolu   : {self.file_size - non_00:,} byte",
            f"  Veri baytı  : {used:,} byte ({used/self.file_size*100:.1f}%)",
            "",
            "  ── Checksum ──",
            f"  Basit toplam: 0x{checksum_simple(self.raw):02X}",
            f"  XOR         : 0x{checksum_xor(self.raw):02X}",
            f"  CRC-32      : 0x{checksum_crc32(self.raw):08X}",
            "=" * 60,
        ]
        return "\n".join(lines)

    # ── hex dump ─────────────────────────────────────────────

    def dump(self, offset: int = 0, length: int = 256) -> str:
        """Belirli bir aralığın hex dumpını döndür."""
        chunk = self.raw[offset:offset+length]
        return hex_dump(chunk, start_offset=offset)

    def dump_header(self) -> str:
        return hex_dump(self.header, start_offset=0)

    def dump_payload(self, length: int = 256) -> str:
        return hex_dump(self.payload[:length], start_offset=HEADER_SIZE)

    # ── arama ────────────────────────────────────────────────

    def find_pattern(self, pattern: bytes) -> list[int]:
        """Byte dizisini arar, bulunan offset listesini döndürür."""
        offsets = []
        start = 0
        while True:
            pos = self.raw.find(pattern, start)
            if pos == -1:
                break
            offsets.append(pos)
            start = pos + 1
        return offsets

    def find_string(self, text: str, encoding: str = "utf-8") -> list[int]:
        """Metin stringini arar."""
        return self.find_pattern(text.encode(encoding))

    # ── düzenleme ────────────────────────────────────────────

    def patch_bytes(self, offset: int, new_bytes: bytes) -> None:
        """Belirtilen offset'ten itibaren baytları değiştir."""
        if offset < 0 or offset + len(new_bytes) > self.file_size:
            raise ValueError(f"Geçersiz offset/uzunluk: offset={offset}, len={len(new_bytes)}, "
                             f"dosya boyutu={self.file_size}")
        data = bytearray(self.raw)
        data[offset:offset+len(new_bytes)] = new_bytes
        self.raw = bytes(data)
        self._parse()
        print(f"[✓] {len(new_bytes)} byte, offset 0x{offset:08X} ({offset}) konumuna yazıldı.")

    def patch_hex(self, offset: int, hex_string: str) -> None:
        """Hex string olarak verilen baytları yaz (örn: 'DEADBEEF')."""
        hex_string = hex_string.replace(" ", "").replace("0x", "")
        new_bytes = bytes.fromhex(hex_string)
        self.patch_bytes(offset, new_bytes)

    def patch_uint8(self, offset: int, value: int) -> None:
        self.patch_bytes(offset, struct.pack("B", value & 0xFF))

    def patch_uint16_le(self, offset: int, value: int) -> None:
        self.patch_bytes(offset, struct.pack("<H", value & 0xFFFF))

    def patch_uint32_le(self, offset: int, value: int) -> None:
        self.patch_bytes(offset, struct.pack("<I", value & 0xFFFFFFFF))

    def patch_string(self, offset: int, text: str, encoding: str = "utf-8",
                     pad_to: int = 0, pad_byte: int = 0x00) -> None:
        """Belirtilen konuma string yaz, isteğe bağlı olarak belirli uzunluğa pad'le."""
        raw_text = text.encode(encoding)
        if pad_to > len(raw_text):
            raw_text = raw_text + bytes([pad_byte] * (pad_to - len(raw_text)))
        self.patch_bytes(offset, raw_text)

    def fill_range(self, offset: int, length: int, fill: int = 0xFF) -> None:
        """Belirli aralığı tek bir baytla doldur."""
        self.patch_bytes(offset, bytes([fill & 0xFF] * length))

    # ── okuma ────────────────────────────────────────────────

    def read_uint8(self, offset: int) -> int:
        return self.raw[offset]

    def read_uint16_le(self, offset: int) -> int:
        return struct.unpack_from("<H", self.raw, offset)[0]

    def read_uint32_le(self, offset: int) -> int:
        return struct.unpack_from("<I", self.raw, offset)[0]

    def read_string(self, offset: int, length: int, encoding: str = "utf-8") -> str:
        raw = self.raw[offset:offset+length]
        return raw.decode(encoding, errors="replace").rstrip("\x00")

    # ── kaydetme ─────────────────────────────────────────────

    def save(self, path: str = "", backup: bool = True) -> str:
        """
        Dosyayı kaydet.
        path boş bırakılırsa orijinal dosyanın üzerine yazar.
        backup=True ise önce .bak yedeği alır.
        """
        if not path:
            path = self.file_path

        if backup and os.path.isfile(path):
            ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
            bak = f"{path}.{ts}.bak"
            shutil.copy2(path, bak)
            print(f"[i] Yedek oluşturuldu: {bak}")

        with open(path, "wb") as f:
            f.write(self.raw)

        print(f"[✓] Kaydedildi: {path}  ({len(self.raw):,} byte)")
        return path

    def export_payload(self, path: str) -> None:
        """Sadece payload kısmını (header'sız) dışa aktar."""
        with open(path, "wb") as f:
            f.write(self.payload)
        print(f"[✓] Payload dışa aktarıldı: {path}  ({len(self.payload):,} byte)")

    def import_payload(self, path: str) -> None:
        """Dışarıdan bir payload dosyası okuyup mevcut payload'ı değiştir."""
        with open(path, "rb") as f:
            new_payload = f.read()
        data = bytearray(self.raw)
        data[HEADER_SIZE:] = new_payload
        self.raw = bytes(data)
        self._parse()
        print(f"[✓] Payload içe aktarıldı: {path}  ({len(new_payload):,} byte)")


# ─────────────────────────────────────────────────────────────
# İNTERAKTİF MENÜ
# ─────────────────────────────────────────────────────────────

def interactive_menu(kit: KitProBin) -> None:
    """Basit komut satırı menüsü."""
    menu = """
┌─────────────────────────────────────────────────────┐
│              KIT-PRO BIN EDİTÖRÜ                    │
├──────┬──────────────────────────────────────────────┤
│  1   │ Dosya bilgisi / özet                         │
│  2   │ Hex dump (offset ve uzunluk seç)             │
│  3   │ Header dump                                  │
│  4   │ Pattern / string ara                         │
│  5   │ Byte oku (offset)                            │
│  6   │ Byte yaz (hex string)                        │
│  7   │ Uint8 yaz                                    │
│  8   │ Uint16-LE yaz                                │
│  9   │ Uint32-LE yaz                                │
│ 10   │ String yaz                                   │
│ 11   │ Aralığı doldur (fill)                        │
│ 12   │ Payload'ı dışa aktar                         │
│ 13   │ Payload'ı içe aktar                          │
│ 14   │ Kaydet (orijinal dosya)                      │
│ 15   │ Farklı kaydet                                │
│  0   │ Çıkış                                        │
└──────┴──────────────────────────────────────────────┘
"""

    while True:
        print(menu)
        choice = input("Seçim: ").strip()

        if choice == "0":
            print("Çıkış.")
            break

        elif choice == "1":
            print(kit.info())

        elif choice == "2":
            try:
                off = int(input("  Offset (hex veya dec, ör: 0x100 ya da 256): "), 0)
                lng = int(input("  Uzunluk (byte): ") or "256")
                print(kit.dump(off, lng))
            except ValueError as e:
                print(f"[!] Hatalı giriş: {e}")

        elif choice == "3":
            print(kit.dump_header())

        elif choice == "4":
            mode = input("  Ara [h=hex / s=string]: ").strip().lower()
            if mode == "h":
                raw_in = input("  Hex pattern (ör: DEADBEEF): ").replace(" ", "")
                try:
                    pat = bytes.fromhex(raw_in)
                    offsets = kit.find_pattern(pat)
                except ValueError as e:
                    print(f"[!] {e}")
                    continue
            else:
                txt = input("  String: ")
                offsets = kit.find_string(txt)

            if offsets:
                print(f"  {len(offsets)} adet bulundu:")
                for o in offsets[:30]:
                    print(f"    0x{o:08X}  ({o})")
                if len(offsets) > 30:
                    print(f"    ... ve {len(offsets)-30} tane daha.")
            else:
                print("  Bulunamadı.")

        elif choice == "5":
            try:
                off = int(input("  Offset: "), 0)
                v8  = kit.read_uint8(off)
                v16 = kit.read_uint16_le(off) if off + 2 <= kit.file_size else 0
                v32 = kit.read_uint32_le(off) if off + 4 <= kit.file_size else 0
                print(f"  [0x{off:08X}]  uint8=0x{v8:02X}({v8})  "
                      f"uint16-LE=0x{v16:04X}({v16})  uint32-LE=0x{v32:08X}({v32})")
                print("  Hex dump:")
                print(kit.dump(off, 32))
            except Exception as e:
                print(f"[!] {e}")

        elif choice == "6":
            try:
                off = int(input("  Offset: "), 0)
                hx  = input("  Hex değer (ör: AABB00FF): ")
                kit.patch_hex(off, hx)
            except Exception as e:
                print(f"[!] {e}")

        elif choice == "7":
            try:
                off = int(input("  Offset: "), 0)
                val = int(input("  Uint8 değeri (0-255): "), 0)
                kit.patch_uint8(off, val)
            except Exception as e:
                print(f"[!] {e}")

        elif choice == "8":
            try:
                off = int(input("  Offset: "), 0)
                val = int(input("  Uint16-LE değeri: "), 0)
                kit.patch_uint16_le(off, val)
            except Exception as e:
                print(f"[!] {e}")

        elif choice == "9":
            try:
                off = int(input("  Offset: "), 0)
                val = int(input("  Uint32-LE değeri: "), 0)
                kit.patch_uint32_le(off, val)
            except Exception as e:
                print(f"[!] {e}")

        elif choice == "10":
            try:
                off  = int(input("  Offset: "), 0)
                txt  = input("  String: ")
                pad  = int(input("  Pad uzunluğu (0=yok): ") or "0")
                kit.patch_string(off, txt, pad_to=pad)
            except Exception as e:
                print(f"[!] {e}")

        elif choice == "11":
            try:
                off  = int(input("  Başlangıç offset: "), 0)
                lng  = int(input("  Uzunluk (byte): "))
                fill = int(input("  Dolgu baytı (ör: 0xFF): "), 0)
                kit.fill_range(off, lng, fill)
            except Exception as e:
                print(f"[!] {e}")

        elif choice == "12":
            path = input("  Çıktı dosyası (ör: payload.bin): ").strip()
            try:
                kit.export_payload(path)
            except Exception as e:
                print(f"[!] {e}")

        elif choice == "13":
            path = input("  Payload dosyası: ").strip()
            try:
                kit.import_payload(path)
            except Exception as e:
                print(f"[!] {e}")

        elif choice == "14":
            backup = input("  Yedek al? (E/h): ").strip().lower() not in ("h", "n", "hayır")
            try:
                kit.save(backup=backup)
            except Exception as e:
                print(f"[!] {e}")

        elif choice == "15":
            path = input("  Kayıt yolu: ").strip()
            backup = input("  Yedek al? (E/h): ").strip().lower() not in ("h", "n", "hayır")
            try:
                kit.save(path, backup=backup)
            except Exception as e:
                print(f"[!] {e}")

        else:
            print("  Geçersiz seçim.")


# ─────────────────────────────────────────────────────────────
# SCRIPT ÖRNEĞİ  (doğrudan düzenleme yapmak için)
# ─────────────────────────────────────────────────────────────

def example_script_usage():
    """
    Örnek: Kit-Pro.bin dosyasını kod ile decode et, düzenle ve kaydet.
    Bu fonksiyonu kendi ihtiyacınıza göre özelleştirin.
    """
    kit = KitProBin()
    kit.load("Kit-Pro.bin")

    # ── 1. Dosya bilgisi ──────────────────────────────────────
    print(kit.info())

    # ── 2. İlk 256 byte'ı hex dump ───────────────────────────
    print("\n── İlk 256 byte ──")
    print(kit.dump(0, 256))

    # ── 3. Belirli bir string ara ─────────────────────────────
    offsets = kit.find_string("KIT")
    print(f"\n'KIT' stringi: {offsets}")

    # ── 4. Örnek: offset 0'daki magic'i oku ──────────────────
    magic = kit.read_string(0, 8)
    print(f"\nMagic: {magic!r}")

    # ── 5. Örnek düzenleme: bir baytı değiştir ───────────────
    #  (aşağıdaki satırı YORUMDAN ÇIKARIN ve offset/değeri kendinize göre ayarlayın)
    # kit.patch_uint8(0x100, 0x42)

    # ── 6. Kaydet ─────────────────────────────────────────────
    #  (aşağıdaki satırı YORUMDAN ÇIKARIN)
    # kit.save("Kit-Pro-modified.bin", backup=False)

    print("\n[i] Düzenleme yapmak için example_script_usage() içindeki")
    print("    yorum satırlarını kaldırın veya interaktif menüyü kullanın.")


# ─────────────────────────────────────────────────────────────
# GİRİŞ NOKTASI
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Komut satırından dosya adı alınabilir, yoksa varsayılan kullanılır
    bin_path = sys.argv[1] if len(sys.argv) > 1 else "Kit-Pro.bin"

    kit = KitProBin()
    try:
        kit.load(bin_path)
    except Exception as e:
        print(f"[!] Dosya yüklenemedi: {e}")
        sys.exit(1)

    # Menü modu (--script argümanıyla örnek script çalıştırılabilir)
    if len(sys.argv) > 2 and sys.argv[2] == "--script":
        example_script_usage()
    else:
        interactive_menu(kit)
