package com.tamperonly.app

/**
 * TamperOnlyEnabler
 *
 * This class does ONE thing and ONE thing only:
 * Enable the Tag Tamper Detection feature on an NTAG 424 DNA TT chip.
 *
 * What it does:
 *   1. Select the NTAG 424 DNA application
 *   2. Authenticate with AppMasterKey (Key 0) using the FACTORY key (all zeros)
 *   3. Send SetConfiguration Option 07h to enable tamper detection
 *      - TTStatusKey = Key 0 (AppMasterKey) — most secure default
 *
 * What it does NOT do:
 *   - Does NOT change any keys (App keys 0-4 remain unchanged)
 *   - Does NOT change the NDEF file content
 *   - Does NOT change SDM settings
 *   - Does NOT change file access rights
 *   - Does NOT change PICC configuration
 *   - Does NOT change any other settings
 *
 * Reference: NXP NT4H2421Tx datasheet
 *   - Section 10.5.1 SetConfiguration
 *   - Option 07h: Tag Tamper configuration (TT-only chips)
 *   - Table 50: SetConfigOptionList — Option 07h data:
 *       Byte 0: TTEnable (1 = enable)
 *       Byte 1: TTStatusKeyNo (key number for GetTTStatus, 0x00 = AppMasterKey)
 *
 * Note: Once enabled, tamper detection CANNOT be disabled again!
 */
class TamperOnlyEnabler(
    private val communicator: Ntag424Communicator,
    private val logger: (String) -> Unit
) {
    // Factory default key: 16 bytes of 0x00
    private val FACTORY_KEY = ByteArray(16) { 0x00 }

    data class Result(val success: Boolean, val message: String)

    fun enableTamperDetection(): Result {
        return try {
            // Step 1: Select the NTAG 424 DNA application
            logger("Schritt 1: NTAG 424 DNA Anwendung auswählen...")
            communicator.selectApplication()

            // Step 2: Authenticate with AppMasterKey (Key 0) using factory key
            logger("\nSchritt 2: Authentifizierung mit AppMasterKey (Key 0)...")
            logger("  Verwende Standard-Werksschlüssel (16x 0x00)")
            val authenticated = communicator.authenticateEV2First(0, FACTORY_KEY)

            if (!authenticated) {
                return Result(
                    false,
                    "Authentifizierung fehlgeschlagen. Chip hat möglicherweise bereits einen angepassten AppMasterKey."
                )
            }

            // Step 3: SetConfiguration Option 07h — enable tamper detection
            // Data bytes:
            //   Byte 0: TTEnable = 0x01 (1 = enable tamper detection)
            //   Byte 1: TTStatusKeyNo = 0x00 (use AppMasterKey for GetTTStatus)
            logger("\nSchritt 3: Tamper-Erkennung aktivieren (SetConfiguration Option 07h)...")
            logger("  TTEnable = 0x01 (aktivieren)")
            logger("  TTStatusKeyNo = 0x00 (AppMasterKey)")

            val tamperConfigData = byteArrayOf(
                0x01.toByte(),  // TTEnable = 1 (enable)
                0x00.toByte()   // TTStatusKeyNo = 0 (AppMasterKey)
            )

            communicator.setConfiguration(0x07.toByte(), tamperConfigData)

            // Optional Step 4: Verify tamper status
            logger("\nSchritt 4: Tamper-Status prüfen...")
            val status = try {
                communicator.getTTStatus()
            } catch (e: Exception) {
                logger("  Status-Abfrage fehlgeschlagen: ${e.message}")
                "unbekannt"
            }
            logger("  Tamper-Status: $status")

            val statusMsg = when {
                status.startsWith("CC") || status.contains("aktiviert") ->
                    "Tamper-Erkennung aktiv. Status: $status (CC = Schleife intakt)"
                status == "II (nicht aktiviert)" ->
                    "Warnung: Status zeigt 'nicht aktiviert' — evtl. Chip-Reset nötig"
                else -> "Aktiviert. Status: $status"
            }

            Result(true, statusMsg)

        } catch (e: Ntag424Exception) {
            Result(false, e.message ?: "Unbekannter NTAG 424 Fehler")
        } catch (e: Exception) {
            Result(false, "Fehler: ${e.message}")
        }
    }
}
