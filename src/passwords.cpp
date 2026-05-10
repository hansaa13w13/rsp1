#include <Preferences.h>
#include "passwords.h"
#include "definitions.h"

static Preferences prefs;

void passwords_init() {
  prefs.begin("deauther", false);
}

bool passwords_save(const String &ssid, const String &password) {
  int count = prefs.getInt("count", 0);
  if (count >= MAX_PASSWORDS) return false;

  char ssid_key[8], pass_key[8];
  snprintf(ssid_key, sizeof(ssid_key), "ss%d", count);
  snprintf(pass_key, sizeof(pass_key), "pw%d", count);

  prefs.putString(ssid_key, ssid);
  prefs.putString(pass_key, password);
  prefs.putInt("count", count + 1);

  DEBUG_PRINT("Sifre kaydedildi: ");
  DEBUG_PRINTLN(password);
  return true;
}

int passwords_count() {
  return prefs.getInt("count", 0);
}

SavedPassword passwords_get(int index) {
  SavedPassword sp;
  if (index < 0 || index >= passwords_count()) return sp;

  char ssid_key[8], pass_key[8];
  snprintf(ssid_key, sizeof(ssid_key), "ss%d", index);
  snprintf(pass_key, sizeof(pass_key), "pw%d", index);

  sp.ssid     = prefs.getString(ssid_key, "");
  sp.password = prefs.getString(pass_key, "");
  return sp;
}

void passwords_delete(int index) {
  int count = passwords_count();
  if (index < 0 || index >= count) return;

  // Shift entries after index down by one
  for (int i = index; i < count - 1; i++) {
    char ssid_src[8], pass_src[8], ssid_dst[8], pass_dst[8];
    snprintf(ssid_src, sizeof(ssid_src), "ss%d", i + 1);
    snprintf(pass_src, sizeof(pass_src), "pw%d", i + 1);
    snprintf(ssid_dst, sizeof(ssid_dst), "ss%d", i);
    snprintf(pass_dst, sizeof(pass_dst), "pw%d", i);

    prefs.putString(ssid_dst, prefs.getString(ssid_src, ""));
    prefs.putString(pass_dst, prefs.getString(pass_src, ""));
  }

  // Remove last slot
  char ssid_last[8], pass_last[8];
  snprintf(ssid_last, sizeof(ssid_last), "ss%d", count - 1);
  snprintf(pass_last, sizeof(pass_last), "pw%d", count - 1);
  prefs.remove(ssid_last);
  prefs.remove(pass_last);
  prefs.putInt("count", count - 1);
}

void passwords_clear_all() {
  prefs.clear();
}
