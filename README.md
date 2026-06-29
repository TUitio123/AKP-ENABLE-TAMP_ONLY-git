# 424DNA TT — Tamper Enable App

Android-App zum **ausschließlichen Aktivieren der Tamper-Erkennung** auf NXP NTAG 424 DNA TT Chips.

## Was diese App macht

| Funktion | Status |
|---|---|
| Tamper-Erkennung aktivieren | ✅ JA |
| Schlüssel ändern | ❌ NEIN |
| NDEF-Inhalt ändern | ❌ NEIN |
| SDM-Einstellungen ändern | ❌ NEIN |
| Andere Konfigurationen ändern | ❌ NEIN |

## Technische Details

Die App sendet ausschließlich:
1. **ISO SelectFile** — Wählt die NTAG 424 DNA Anwendung aus
2. **AuthenticateEV2First (Key 0)** — Authentifizierung mit Standard-Werksschlüssel (16× 0x00)
3. **SetConfiguration Option 07h** — Aktiviert Tamper-Erkennung

### SetConfiguration Option 07h Daten:
```
Byte 0: TTEnable = 0x01  (Tamper-Erkennung aktivieren)
Byte 1: TTStatusKeyNo = 0x00  (AppMasterKey für GetTTStatus)
```

## Voraussetzungen

- Android 6.0+ (minSdk 23)
- NFC-fähiges Android-Gerät
- NTAG 424 DNA TT Chip mit **Standard-Werksschlüssel** (16× 0x00)

> ⚠️ **WICHTIG**: Die Tamper-Erkennung kann nach dem Aktivieren **nicht mehr deaktiviert** werden!

## APK herunterladen

Die APK wird automatisch via GitHub Actions gebaut. Unter **Releases** oder **Actions** → **Artifacts** verfügbar.

## Referenz

- NXP NT4H2421Tx Datasheet Rev 3.0
  - Section 10.5.1: SetConfiguration
  - Table 50: SetConfigOptionList (Option 07h)
  - Section 11.9: GetTTStatus
