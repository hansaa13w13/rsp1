#!/usr/bin/env python3
"""
Kit-Pro.bin PROTECT Bypass Patcher
-----------------------------------
Kit-Pro.bin cihaz kayit kontrolunu (PROTECT sistemi) bypass eder.
Sorun: Cihaz MAC adresini kontrol eder, kayitli degilse HTTP sunucu hic baslamaz.
Cozum: Kayit kontrol dalini (cbnz -> b) koşulsuz "kayitli" yoluna yonlendir.
Uretir: Kit-Pro-Unlocked.bin (flash'a hazir)
"""

import struct, sys
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

# ---------------------------------------------------------------------------
# Sabitler
# ---------------------------------------------------------------------------

# KM4 image binary layout:
#   Binary offset 0x1B020  ->  runtime address 0x0E000020
KM4_BIN_START  = 0x1B020
KM4_RT_BASE    = 0x0E000020

def rt_to_bin(rt_addr):
    return (rt_addr - KM4_RT_BASE) + KM4_BIN_START

def bin_to_rt(bin_off):
    return (bin_off - KM4_BIN_START) + KM4_RT_BASE

# ---------------------------------------------------------------------------
# PATCH-01: PROTECT karar dali bypass
# ---------------------------------------------------------------------------
# Adres: 0x0E000B32 (binary: 0x1BB32)
# Eski: cbnz r0, #0xe000b7a  (10 BB)
#        = r0!=0 ise "Kayitli" yoluna git, r0==0 ise "KAYITSIZ" yoluna git (HTTP baslamaz)
# Yeni: b    #0xe000b7a      (22 E0)
#        = Her zaman "Kayitli" yoluna git -> HTTP sunucu baslar

PATCH_BIN_OFFSET = rt_to_bin(0x0E000B32)   # = 0x1BB32
PATCH_OLD        = bytes([0x10, 0xBB])      # cbnz r0, #0xe000b7a
PATCH_NEW        = bytes([0x22, 0xE0])      # b    #0xe000b7a

# ---------------------------------------------------------------------------
# Doğrulama: Capstone ile decode
# ---------------------------------------------------------------------------

def decode_instr(code, addr, label):
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    for insn in md.disasm(code, addr):
        print(f"    [{label}] 0x{insn.address:08X}  {insn.bytes.hex():<8}  {insn.mnemonic} {insn.op_str}")

# ---------------------------------------------------------------------------
# Ana işlem
# ---------------------------------------------------------------------------

def main():
    src  = "Kit-Pro.bin"
    dest = "Kit-Pro-Unlocked.bin"

    print("=" * 64)
    print("  KIT-PRO.BIN — PROTECT Bypass Patcher")
    print("=" * 64)

    print(f"\n[*] Yukleniyor: {src}")
    with open(src, "rb") as f:
        data = bytearray(f.read())
    original_len = len(data)
    print(f"    Boyut: {original_len:,} byte")

    print(f"\n[*] PROTECT sistemi analizi:")
    print(f"    KM4 image binary offset : 0x{KM4_BIN_START:X}")
    print(f"    KM4 runtime base        : 0x{KM4_RT_BASE:X}")
    print(f"    Karar dali binary offset: 0x{PATCH_BIN_OFFSET:X}")
    print(f"    Karar dali runtime addr : 0x{bin_to_rt(PATCH_BIN_OFFSET):08X}")

    # Mevcut byte'lari kontrol et
    actual = bytes(data[PATCH_BIN_OFFSET:PATCH_BIN_OFFSET+2])
    print(f"\n[*] Binary 0x{PATCH_BIN_OFFSET:X} mevcut: {actual.hex()}")
    if actual != PATCH_OLD:
        print(f"    [!] HATA: Beklenen {PATCH_OLD.hex()}, mevcut {actual.hex()}")
        print(f"        Binary farklı veya offset yanlis.")
        sys.exit(1)
    print(f"    [✓] Beklenen byte'lar dogrulandı")

    print(f"\n── PATCH-01: Kayit Kontrol Dali Bypass ─────────────────")
    print(f"    Eski instruction:")
    decode_instr(PATCH_OLD, bin_to_rt(PATCH_BIN_OFFSET), "ESKI")
    print(f"    Yeni instruction:")
    decode_instr(PATCH_NEW, bin_to_rt(PATCH_BIN_OFFSET), "YENI")

    data[PATCH_BIN_OFFSET:PATCH_BIN_OFFSET+2] = PATCH_NEW
    print(f"    [✓] Patch uygulandi @ binary 0x{PATCH_BIN_OFFSET:X}")

    print(f"\n── Boyut dogrulama ──────────────────────────────────────")
    if len(data) == original_len:
        print(f"    [✓] Boyut korundu: {len(data):,} byte")
    else:
        print(f"    [!] BOYUT DEGISTI: {original_len} -> {len(data)}")
        sys.exit(1)

    print(f"\n── Dogrulama taramasi ───────────────────────────────────")
    # Patch uygulandiktan sonra byte'i kontrol et
    patched = bytes(data[PATCH_BIN_OFFSET:PATCH_BIN_OFFSET+2])
    if patched == PATCH_NEW:
        print(f"    [✓] Patch dogrulandi: {patched.hex()} (b #0xe000b7a)")
    else:
        print(f"    [!] Patch dogrulanamadi: {patched.hex()}")
        sys.exit(1)

    # Pro binary'de trial stringleri yok (bunlar sadece Trial'da var)
    # Ama 192.168.1.1 yoklugunu kontrol et
    ip_check = bytes(data).find(b'192.168.1.1')
    if ip_check == -1:
        print(f"    [~] 192.168.1.1 IP mevcut degil (cihaz DHCP/dinamik IP kullanıyor)")
    else:
        print(f"    [✓] 192.168.1.1 @ 0x{ip_check:X}")

    print(f"\n── Kaydediliyor ─────────────────────────────────────────")
    with open(dest, "wb") as f:
        f.write(data)
    print(f"    [✓] Kaydedildi: {dest}  ({len(data):,} byte)")

    print(f"\n{'='*64}")
    print(f"  BASARILI — Kit-Pro-Unlocked.bin flash'a hazir!")
    print(f"")
    print(f"  Degisiklikler:")
    print(f"    * PROTECT kayit kontrolu devre disi (her zaman kayitli)")
    print(f"    * HTTP sunucu normalde basliyor (port 80)")
    print(f"    * Tum ozellikler aktif (Evil-Twin, Deauth, Beacon, vb.)")
    print(f"")
    print(f"  Not: Cihaz ilk acilista 192.168.x.x IP atayacak.")
    print(f"       WiFiPKit SSID'ye baglanip IP'yi kontrol edin.")
    print(f"{'='*64}")

if __name__ == "__main__":
    main()
