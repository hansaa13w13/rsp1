#ifndef PASSWORDS_H
#define PASSWORDS_H

#include <Arduino.h>

#define MAX_PASSWORDS 30

struct SavedPassword {
  String ssid;
  String password;
};

void     passwords_init();
bool     passwords_save(const String &ssid, const String &password);
int      passwords_count();
SavedPassword passwords_get(int index);
void     passwords_delete(int index);
void     passwords_clear_all();

#endif
