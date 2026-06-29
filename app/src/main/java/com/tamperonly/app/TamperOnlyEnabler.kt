package com.tamperonly.app

/**
 * TamperOnlyEnabler
 *
 * Einzige Aufgabe: Tamper-Erkennung auf NTAG 424 DNA TT Chip aktivieren.
 *
 * Was passiert:
 *   1. ISO SelectFile (Anwendung auswählen)
 *   2. Authentifizierung mit AppMasterKey (Key 0) — automatisch AES oder LRP
 *   3. SetConfiguration Option 07h → TTEnable=1, TTStatusKeyNo=0
 *
 * Was NICHT passiert:
 *   - Kein Schlüssel wird geändert
 *   - Kein NDEF-Inhalt wird geändert
 *   - Keine anderen Einstellungen werden geändert
 *
 * Schlüssel: Standard-Werksschlüssel = 16× 0x00 (AES-128)
 *   Auch wenn der Chip 32 Bytes speichert, ist der aktive Schlüssel 16× 0x00.
 */
class TamperOnlyEnabler(
    private val communicator: Ntag424Communicator,
    private val logger: (String) -> Unit
) {
    // Werksschlüssel: 16 Bytes, alle 0x00
    private val FACTORY_KEY = ByteArray(16) { 0x00 }

    data class Result(val success: Boolean, val message: String)

    fun enableTamperDetection(): Result {
        return try {
            // Schritt 1: Anwendung auswählen
            logger("Schritt 1: NTAG 424 DNA Anwendung auswählen...")
            communicator.selectApplication()

            // Schritt 2: Authentifizierung (auto-detect AES vs LRP)
            logger("\nSchritt 2: Authentifizierung Key #0 (Werksschlüssel 16× 0x00)...")
            val ok = communicator.authenticateFirst(0, FACTORY_KEY)
            if (!ok) {
                return Result(false,
                    "Authentifizierung fehlgeschlagen.\n" +
                    "Mögliche Ursachen:\n" +
                    "• AppMasterKey wurde geändert\n" +
                    "• Tamper-Erkennung bereits aktiviert"
                )
            }

            val mode = if (communicator.isLrpMode) "LRP" else "AES EV2"
            logger("  Modus: $mode")

            // Schritt 3: SetConfiguration Option 07h
            logger("\nSchritt 3: Tamper-Erkennung aktivieren (Option 07h)...")
            logger("  TTEnable      = 0x01 (aktivieren)")
            logger("  TTStatusKeyNo = 0x00 (AppMasterKey)")

            communicator.setConfiguration(
                option = 0x07.toByte(),
                data   = byteArrayOf(
                    0x01.toByte(),  // TTEnable = 1
                    0x00.toByte()   // TTStatusKeyNo = 0 (AppMasterKey)
                )
            )

            Result(true, "Aktiviert via $mode. Chip registriert ab dem nächsten Tap.")

        } catch (e: Ntag424Exception) {
            val hint = when {
                "7E" in (e.message ?: "") -> "\nHinweis: SW=7E = Chip ist im LRP-Modus"
                "9D" in (e.message ?: "") -> "\nHinweis: SW=9D = Keine Berechtigung (Schlüssel geändert?)"
                "AE" in (e.message ?: "") -> "\nHinweis: SW=AE = Falscher Schlüssel"
                else -> ""
            }
            Result(false, (e.message ?: "Unbekannter Fehler") + hint)
        } catch (e: Exception) {
            Result(false, "Fehler: ${e.message}")
        }
    }
}
