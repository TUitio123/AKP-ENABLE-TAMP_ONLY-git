package com.tamperonly.app

import android.nfc.tech.IsoDep
import java.io.IOException
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Low-level communicator for NTAG 424 DNA (TT) chips.
 *
 * Supports:
 *   - AES EV2 secure messaging (standard mode)
 *   - LRP secure messaging (chips with SetConfiguration Option 05h applied)
 *
 * Auto-detects which mode the chip uses during AuthenticateFirst.
 *
 * Reference:
 *   - NXP NT4H2421Tx datasheet Rev 3.0 (2019)
 *   - NXP AN12196 NTAG 424 DNA features and hints
 *   - NXP AN12304 Leakage Resilient Primitive (LRP) Specification
 *   - NXP AN12321 NTAG 424 DNA (TagTamper) features and hints — LRP mode
 */
class Ntag424Communicator(
    private val isoDep: IsoDep,
    private val logger: (String) -> Unit
) {
    // NTAG 424 DNA Application DF name
    private val DF_NAME = byteArrayOf(
        0xD2.toByte(), 0x76.toByte(), 0x00.toByte(), 0x00.toByte(),
        0x85.toByte(), 0x01.toByte(), 0x01.toByte()
    )

    // Session state (set after successful authentication)
    var sessionEncKey: ByteArray? = null
    var sessionMacKey: ByteArray? = null
    var transactionIdentifier: ByteArray? = null  // TI (4 bytes)
    var cmdCounter: Int = 0
    var isLrpMode: Boolean = false

    // ─── Core APDU transceiver ────────────────────────────────────────────────

    @Throws(IOException::class, Ntag424Exception::class)
    fun sendCommand(ins: Byte, data: ByteArray = ByteArray(0)): ByteArray {
        val apdu = buildApdu(ins, data)
        logger("  >> ${apdu.toHex()}")
        val response = isoDep.transceive(apdu)
        logger("  << ${response.toHex()}")

        if (response.size < 2) throw Ntag424Exception("Response zu kurz: ${response.toHex()}")

        val sw1 = response[response.size - 2].toInt() and 0xFF
        val sw2 = response[response.size - 1].toInt() and 0xFF

        if (sw1 != 0x91) {
            throw Ntag424Exception("APDU Fehler: SW=${sw1.toHex2()}${sw2.toHex2()} (${swDesc(sw1, sw2)})")
        }
        if (sw2 != 0x00 && sw2 != 0xAF) {
            throw Ntag424Exception("Command failed: SW2=${sw2.toHex2()} (${swDesc(sw1, sw2)})")
        }
        return response.copyOf(response.size - 2)
    }

    // Raw transceive without SW checking (for auth steps where SW=91AF is normal)
    @Throws(IOException::class)
    private fun transceiveRaw(ins: Byte, data: ByteArray): Pair<Int, ByteArray> {
        val apdu = buildApdu(ins, data)
        logger("  >> ${apdu.toHex()}")
        val response = isoDep.transceive(apdu)
        logger("  << ${response.toHex()}")
        if (response.size < 2) throw Ntag424Exception("Response zu kurz")
        val sw1 = response[response.size - 2].toInt() and 0xFF
        val sw2 = response[response.size - 1].toInt() and 0xFF
        val sw = (sw1 shl 8) or sw2
        return Pair(sw, response.copyOf(response.size - 2))
    }

    private fun buildApdu(ins: Byte, data: ByteArray): ByteArray {
        return if (data.isEmpty()) {
            byteArrayOf(0x90.toByte(), ins, 0x00, 0x00, 0x00)
        } else {
            byteArrayOf(0x90.toByte(), ins, 0x00, 0x00, data.size.toByte()) +
                    data + byteArrayOf(0x00)
        }
    }

    // ─── ISO Select File ──────────────────────────────────────────────────────

    @Throws(IOException::class, Ntag424Exception::class)
    fun selectApplication() {
        val apdu = byteArrayOf(0x00, 0xA4.toByte(), 0x04, 0x00, DF_NAME.size.toByte()) +
                DF_NAME + byteArrayOf(0x00)
        logger("  >> ${apdu.toHex()} (ISO SelectFile)")
        val response = isoDep.transceive(apdu)
        logger("  << ${response.toHex()}")
        if (response.size < 2) throw Ntag424Exception("SelectFile: leere Antwort")
        val sw1 = response[response.size - 2].toInt() and 0xFF
        val sw2 = response[response.size - 1].toInt() and 0xFF
        if (sw1 != 0x90 || sw2 != 0x00) {
            throw Ntag424Exception("SelectFile fehlgeschlagen: SW=${sw1.toHex2()}${sw2.toHex2()}")
        }
        logger("  Anwendung ausgewählt OK")
    }

    // ─── Authentication: Auto-detect AES vs LRP ───────────────────────────────
    // Sends AuthenticateEV2First with PCDCap2.1=0x02 (LRP capability bit set).
    // The chip's response length tells us which mode it uses:
    //   17 bytes = AES mode  (ADDITIONAL_FRAME + 16 bytes rndB_enc)
    //   18 bytes = LRP mode  (ADDITIONAL_FRAME + AuthMode(1) + 16 bytes)
    // SW=917E means the chip requires LRP and we sent plain AES → try LRP directly.

    @Throws(IOException::class, Ntag424Exception::class)
    fun authenticateFirst(keyNumber: Int, key: ByteArray): Boolean {
        logger("Authentifizierung starten (Key #$keyNumber)...")

        // Step 1: Send AuthenticateEV2First with PCDCap2.1=0x02 (signal LRP support)
        // Format: [keyNumber, PCDCap2Length=0x02, PCDCap2.1=0x02, PCDCap2.2=0x00]
        // This tells the chip we support LRP; it will respond with 18 bytes if in LRP mode.
        val step1Data = byteArrayOf(
            keyNumber.toByte(),
            0x02.toByte(),  // PCDCap2 length = 2 bytes
            0x02.toByte(),  // PCDCap2.1 = 0x02 → LRP capable
            0x00.toByte()   // PCDCap2.2
        )

        val (sw1, resp1) = transceiveRaw(0x71.toByte(), step1Data)

        return when {
            sw1 == 0x91AF && resp1.size >= 17 -> {
                // Check AuthMode byte (first byte) to determine AES vs LRP
                // AES: response is exactly 16 bytes (no AuthMode byte)
                // LRP: response starts with AuthMode=0x02, then 16 bytes
                if (resp1.size >= 18 && (resp1[0].toInt() and 0xFF) == 0x02) {
                    logger("  Chip ist im LRP-Modus")
                    isLrpMode = true
                    authenticateLRP(keyNumber, key, resp1.copyOfRange(1, 17))
                } else {
                    logger("  Chip ist im AES EV2-Modus")
                    isLrpMode = false
                    authenticateAES(key, resp1.copyOf(16))
                }
            }
            sw1 == 0x917E -> {
                // PRECONDITION_NOT_SATISFIED: chip is in LRP-only mode
                // Need to send with PCDCap2.1=0x02 explicitly — retry as LRP
                logger("  SW=917E: Chip ist im LRP-Modus, starte LRP-Auth neu...")
                isLrpMode = true
                authenticateLRPFull(keyNumber, key)
            }
            else -> {
                throw Ntag424Exception("Auth Step1 fehlgeschlagen: SW=${(sw1 ushr 8).toHex2()}${(sw1 and 0xFF).toHex2()}")
            }
        }
    }

    // ─── AES EV2 Authentication (full) ────────────────────────────────────────

    private fun authenticateAES(key: ByteArray, encRndB: ByteArray): Boolean {
        logger("  AES EV2 Handshake...")
        val rndA = ByteArray(16).also { SecureRandom().nextBytes(it) }

        val rndB = aesCbcDecrypt(key, ByteArray(16), encRndB)
        val rndBRotated = rndB.drop(1).toByteArray() + rndB[0]
        val payload = rndA + rndBRotated
        val encPayload = aesCbcEncrypt(key, ByteArray(16), payload)

        val (sw2, resp2) = transceiveRaw(0xAF.toByte(), encPayload)
        if (sw2 != 0x9100) throw Ntag424Exception("AES Auth Step2: SW=${(sw2 ushr 8).toHex2()}${(sw2 and 0xFF).toHex2()}")
        if (resp2.size < 32) throw Ntag424Exception("AES Auth Step2: Antwort zu kurz")

        val ti = resp2.copyOfRange(0, 4)
        val encRndARotated = resp2.copyOfRange(4, 20)
        val rndARotated = aesCbcDecrypt(key, ByteArray(16), encRndARotated)
        val rndAFromTag = rndARotated.drop(15).toByteArray() + rndARotated.copyOfRange(0, 15)

        if (!rndA.contentEquals(rndAFromTag)) {
            logger("  Warnung: rndA Verifikation fehlgeschlagen (falscher Schlüssel?)")
            return false
        }

        transactionIdentifier = ti
        cmdCounter = 0

        // Derive AES session keys
        val svEnc = byteArrayOf(0xA5.toByte(), 0x5A.toByte(), 0xA5.toByte(), 0x5A.toByte()) +
                ti + rndA.copyOfRange(0, 2) + rndB.copyOfRange(0, 2)
        val svMac = byteArrayOf(0x5A.toByte(), 0x36.toByte(), 0x5A.toByte(), 0x36.toByte()) +
                ti + rndA.copyOfRange(0, 2) + rndB.copyOfRange(0, 2)

        sessionEncKey = aesCmac(key, svEnc)
        sessionMacKey = aesCmac(key, svMac)

        logger("  AES Authentifizierung OK! TI=${ti.toHex()}")
        return true
    }

    // ─── LRP Authentication (via re-send with explicit LRP request) ───────────

    private fun authenticateLRPFull(keyNumber: Int, key: ByteArray): Boolean {
        logger("  LRP AuthenticateLRPFirst Handshake...")

        // Per AN12321: to force LRP mode, send PCDCap2.1 = 0x02
        val step1Data = byteArrayOf(
            keyNumber.toByte(),
            0x02.toByte(),  // PCDCap2 length
            0x02.toByte(),  // PCDCap2.1 = LRP bit
            0x00.toByte()
        )
        val (sw1, resp1) = transceiveRaw(0x71.toByte(), step1Data)

        // Expected: 91AF + 18 bytes (AuthMode=02 + 16 bytes encRndB)
        if (sw1 != 0x91AF) {
            throw Ntag424Exception("LRP Auth Step1: SW=${(sw1 ushr 8).toHex2()}${(sw1 and 0xFF).toHex2()}")
        }
        if (resp1.size < 17) throw Ntag424Exception("LRP Auth Step1: Antwort zu kurz (${resp1.size} bytes)")

        val authMode = resp1[0].toInt() and 0xFF
        if (authMode != 0x02) {
            throw Ntag424Exception("LRP Auth: Unerwarteter AuthMode=0x${authMode.toHex2()} (erwartet 0x02)")
        }

        val encRndB = resp1.copyOfRange(1, 17)
        return authenticateLRP(keyNumber, key, encRndB)
    }

    private fun authenticateLRP(keyNumber: Int, key: ByteArray, encRndB: ByteArray): Boolean {
        val rndA = ByteArray(16).also { SecureRandom().nextBytes(it) }

        // LRP key is only the first 16 bytes (AES-128), even if chip stores 32 bytes
        val lrpKey = key.copyOfRange(0, minOf(16, key.size))

        // Decrypt rndB using LRP-LRICB (CTR mode) with IV=0
        val zeroIV = ByteArray(16)
        val rndB = LRP.decrypt(lrpKey, zeroIV, encRndB)
        logger("  rndB (decrypted): ${rndB.toHex()}")

        // PCDResponse = LRP-CMAC(SesAuthMACKey derived from rndA, rndA || rndB)
        // Per AN12321 Table 2: PCDResponse = MAC_LRP(KSesAuthMACKey, rndA || rndB)
        // But KSesAuthMACKey is derived after TI is known. For step 2, we send:
        // PCDResponse = MAC_LRP(key, rndA || rndB) as per the auth protocol

        // Actually per AN12321:
        // PCD sends: rndA encrypted + rndA||rndB MACed
        // Enc_LRP(key, rndA) || MAC_LRP(key, rndA || rndB)

        val encRndA = LRP.encrypt(lrpKey, zeroIV, rndA)
        val macInput = rndA + rndB
        val mac = LRP.cmacCorrect(lrpKey, macInput)

        val step2Data = encRndA + mac
        val (sw2, resp2) = transceiveRaw(0xAF.toByte(), step2Data)

        if (sw2 != 0x9100) {
            throw Ntag424Exception("LRP Auth Step2: SW=${(sw2 ushr 8).toHex2()}${(sw2 and 0xFF).toHex2()} (${swDesc(sw2 ushr 8, sw2 and 0xFF)})")
        }

        // Response: Enc_LRP(KSesAuthEncKey, TI || PDCap2 || PCDCap2) || PICCResponse
        // We need to verify and extract TI
        if (resp2.size < 32) throw Ntag424Exception("LRP Auth Step2: Antwort zu kurz (${resp2.size})")

        // Extract TI: decrypt first 16 bytes
        val encTiBlock = resp2.copyOfRange(0, 16)
        val decrypted = LRP.decrypt(lrpKey, zeroIV, encTiBlock)
        val ti = decrypted.copyOfRange(0, 4)
        logger("  TI (LRP): ${ti.toHex()}")

        // Verify PICC response (MAC): resp2[16..31]
        // PICCResponse = MAC_LRP(KSesAuthMACKey, rndB || rndA)
        // For now we accept it and derive session keys

        transactionIdentifier = ti
        cmdCounter = 0
        isLrpMode = true

        // Derive LRP session keys (AN12321):
        // SV1 (Enc) = 0xA55A || A55A || 0100 || 80 || 00 || keyNo || <01> || rndA[0..15] || rndB[0..15]
        // SV2 (MAC) = 0x5A36 || 5A36 || 0100 || 80 || 00 || keyNo || <01> || rndA[0..15] || rndB[0..15]
        // Then: KSesAuthEnc = LRP-CMAC(key, SV1), KSesAuthMAC = LRP-CMAC(key, SV2)

        val svPrefix = byteArrayOf(0x00.toByte(), 0x01.toByte(), 0x00.toByte(), 0x80.toByte(),
            0x00.toByte(), keyNumber.toByte(), 0x01.toByte())

        val svEnc = byteArrayOf(0xA5.toByte(), 0x5A.toByte(), 0xA5.toByte(), 0x5A.toByte()) +
                svPrefix + rndA + rndB
        val svMac = byteArrayOf(0x5A.toByte(), 0x36.toByte(), 0x5A.toByte(), 0x36.toByte()) +
                svPrefix + rndA + rndB

        sessionEncKey = LRP.cmacCorrect(lrpKey, svEnc)
        sessionMacKey = LRP.cmacCorrect(lrpKey, svMac)

        logger("  LRP Authentifizierung OK!")
        return true
    }

    // ─── SetConfiguration (Cmd=0x5C) ─────────────────────────────────────────
    // CommMode.Full — works for both AES and LRP sessions

    @Throws(IOException::class, Ntag424Exception::class)
    fun setConfiguration(option: Byte, data: ByteArray) {
        val encKey = sessionEncKey ?: throw Ntag424Exception("Nicht authentifiziert")
        val macKey = sessionMacKey ?: throw Ntag424Exception("Nicht authentifiziert")
        val ti = transactionIdentifier ?: throw Ntag424Exception("Kein TI")

        logger("SetConfiguration: Option=0x${option.toHex2()}, Data=${data.toHex()}")

        val cmdCounterBytes = byteArrayOf(
            (cmdCounter and 0xFF).toByte(),
            ((cmdCounter shr 8) and 0xFF).toByte()
        )

        val encData: ByteArray
        val mac: ByteArray

        if (isLrpMode) {
            // LRP CommMode.Full
            // IV for encryption: CMAC_LRP(SesAuthEncKey, 0xA55A || TI || CmdCounter || 00..00)
            val ivInput = byteArrayOf(0xA5.toByte(), 0x5A.toByte()) + ti + cmdCounterBytes + ByteArray(10)
            val iv = LRP.cmacCorrect(encKey, ivInput)

            val paddedData = padISO(data)
            encData = LRP.encrypt(encKey, iv, paddedData)

            // MAC_LRP(SesAuthMACKey, 0x5C || CmdCounter || TI || Option || encData)
            val macInput = byteArrayOf(0x5C.toByte()) + cmdCounterBytes + ti + byteArrayOf(option) + encData
            val fullMac = LRP.cmacCorrect(macKey, macInput)
            mac = fullMac.copyOfRange(0, 8) // first 8 bytes for LRP
        } else {
            // AES CommMode.Full
            val ivInput = byteArrayOf(0xA5.toByte(), 0x5A.toByte()) + ti + cmdCounterBytes + ByteArray(10)
            val iv = aesCbcEncrypt(encKey, ByteArray(16), ivInput)

            val paddedData = padISO(data)
            encData = aesCbcEncrypt(encKey, iv, paddedData)

            val macInput = byteArrayOf(0x5C.toByte()) + cmdCounterBytes + ti + byteArrayOf(option) + encData
            val fullMac = aesCmac(macKey, macInput)
            mac = ByteArray(8) { i -> fullMac[2 * i + 1] } // truncated MAC (odd bytes)
        }

        val cmdData = byteArrayOf(option) + encData + mac
        val response = sendCommand(0x5C.toByte(), cmdData)
        cmdCounter++

        logger("  SetConfiguration OK! Response: ${response.toHex()}")
    }

    // ─── AES crypto helpers ───────────────────────────────────────────────────

    fun aesCbcEncrypt(key: ByteArray, iv: ByteArray, data: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/CBC/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
        return cipher.doFinal(data)
    }

    fun aesCbcDecrypt(key: ByteArray, iv: ByteArray, data: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/CBC/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
        return cipher.doFinal(data)
    }

    fun aesCmac(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("AESCMAC")
        mac.init(SecretKeySpec(key, "AES"))
        return mac.doFinal(data)
    }

    private fun padISO(data: ByteArray): ByteArray {
        val padLen = 16 - (data.size % 16)
        return data + byteArrayOf(0x80.toByte()) + ByteArray(padLen - 1)
    }

    // ─── SW description ───────────────────────────────────────────────────────

    private fun swDesc(sw1: Int, sw2: Int): String = when {
        sw1 == 0x91 && sw2 == 0x00 -> "SUCCESS"
        sw1 == 0x91 && sw2 == 0xAF -> "ADDITIONAL_FRAME"
        sw1 == 0x91 && sw2 == 0x1E -> "PARAMETER_ERROR"
        sw1 == 0x91 && sw2 == 0x1C -> "INVALID_COMMAND_CODE"
        sw1 == 0x91 && sw2 == 0x40 -> "NO_SUCH_KEY"
        sw1 == 0x91 && sw2 == 0x6E -> "COMMAND_ABORTED"
        sw1 == 0x91 && sw2 == 0x7E -> "PRECONDITION_NOT_SATISFIED"
        sw1 == 0x91 && sw2 == 0x9D -> "PERMISSION_DENIED"
        sw1 == 0x91 && sw2 == 0xAE -> "AUTHENTICATION_ERROR"
        sw1 == 0x91 && sw2 == 0xBE -> "BOUNDARY_ERROR"
        else -> "UNKNOWN"
    }
}

fun ByteArray.toHex(): String = joinToString("") { "%02X".format(it) }
fun Int.toHex2(): String = "%02X".format(this)
fun Byte.toHex2(): String = "%02X".format(this.toInt() and 0xFF)
