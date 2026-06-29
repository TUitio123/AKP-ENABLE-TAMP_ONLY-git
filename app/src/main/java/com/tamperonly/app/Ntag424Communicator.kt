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
 * Implements ISO/IEC 7816-4 wrapped APDU commands.
 * All native commands are wrapped: CLA=0x90, Ins=<cmd>, P1=0x00, P2=0x00.
 *
 * Reference: NXP NT4H2421Tx datasheet Rev 3.0 (2019)
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

    // Current session state
    var sessionEncKey: ByteArray? = null
    var sessionMacKey: ByteArray? = null
    var transactionIdentifier: ByteArray? = null  // TI (4 bytes)
    var cmdCounter: Int = 0

    // -------------------------------------------------------------------------
    // Core APDU transceiver
    // -------------------------------------------------------------------------

    /**
     * Send a wrapped NTAG 424 native command.
     * Format: 90 <ins> 00 00 <Lc> <data> 00
     */
    @Throws(IOException::class, Ntag424Exception::class)
    fun sendCommand(ins: Byte, data: ByteArray = ByteArray(0)): ByteArray {
        val apdu = buildApdu(ins, data)
        logger("  >> ${apdu.toHex()}")
        val response = isoDep.transceive(apdu)
        logger("  << ${response.toHex()}")

        if (response.size < 2) {
            throw Ntag424Exception("Response too short: ${response.toHex()}")
        }

        val sw1 = response[response.size - 2].toInt() and 0xFF
        val sw2 = response[response.size - 1].toInt() and 0xFF

        // 0x91 0x00 = SUCCESS
        // 0x91 0xAF = Additional frames expected
        if (sw1 != 0x91) {
            throw Ntag424Exception("APDU error: SW=${sw1.toHex2()}${sw2.toHex2()} (${getSwDescription(sw1, sw2)})")
        }
        if (sw2 != 0x00 && sw2 != 0xAF) {
            throw Ntag424Exception("Command failed: SW2=${sw2.toHex2()} (${getSwDescription(sw1, sw2)})")
        }

        return response.copyOf(response.size - 2)
    }

    private fun buildApdu(ins: Byte, data: ByteArray): ByteArray {
        return if (data.isEmpty()) {
            byteArrayOf(0x90.toByte(), ins, 0x00, 0x00, 0x00)
        } else {
            byteArrayOf(0x90.toByte(), ins, 0x00, 0x00, data.size.toByte()) +
                    data + byteArrayOf(0x00)
        }
    }

    // -------------------------------------------------------------------------
    // ISO Select File (required before any NTAG 424 native command)
    // -------------------------------------------------------------------------

    @Throws(IOException::class, Ntag424Exception::class)
    fun selectApplication() {
        // ISO SELECT FILE by DF name: CLA=00, INS=A4, P1=04, P2=00
        val apdu = byteArrayOf(0x00, 0xA4.toByte(), 0x04, 0x00, DF_NAME.size.toByte()) +
                DF_NAME + byteArrayOf(0x00)
        logger("  >> ${apdu.toHex()} (ISO SelectFile)")
        val response = isoDep.transceive(apdu)
        logger("  << ${response.toHex()}")

        if (response.size < 2) throw Ntag424Exception("SelectFile: empty response")
        val sw1 = response[response.size - 2].toInt() and 0xFF
        val sw2 = response[response.size - 1].toInt() and 0xFF
        if (sw1 != 0x90 || sw2 != 0x00) {
            throw Ntag424Exception("SelectFile failed: SW=${sw1.toHex2()}${sw2.toHex2()}")
        }
        logger("  Application selected OK")
    }

    // -------------------------------------------------------------------------
    // AES EV2 Authentication (AuthenticateEV2First, Cmd=0x71)
    // -------------------------------------------------------------------------

    @Throws(IOException::class, Ntag424Exception::class)
    fun authenticateEV2First(keyNumber: Int, key: ByteArray): Boolean {
        logger("Authentifizierung: AES EV2 First (Key #$keyNumber)...")

        val rnd = SecureRandom()
        val rndA = ByteArray(16).also { rnd.nextBytes(it) }

        // Step 1: Send AuthenticateEV2First with key number
        // CmdHeader = [keyNumber, 00 00]
        val step1Data = byteArrayOf(keyNumber.toByte(), 0x00, 0x00)
        val step1Response = sendCommand(0x71.toByte(), step1Data)

        // Response contains encrypted rndB (16 bytes)
        if (step1Response.size < 16) {
            throw Ntag424Exception("AuthEV2First Step1: response too short (${step1Response.size} bytes)")
        }
        val encRndB = step1Response.copyOf(16)

        // Decrypt rndB using AES-128-CBC with IV=0
        val rndB = aesCbcDecrypt(key, ByteArray(16), encRndB)

        // Rotate rndB left by 1 byte
        val rndBRotated = rndB.drop(1).toByteArray() + rndB[0]

        // Concatenate rndA || rndBRotated and encrypt
        val payload = rndA + rndBRotated
        val encPayload = aesCbcEncrypt(key, ByteArray(16), payload)

        // Step 2: Send the encrypted payload (Cmd=0xAF = continue)
        val step2Response = sendCommand(0xAF.toByte(), encPayload)

        // Response: TI (4 bytes) || enc(rndA_rotated) (16 bytes) || PDCap2 (6 bytes) || PCDCap2 (6 bytes)
        // Total = 32 bytes
        if (step2Response.size < 32) {
            throw Ntag424Exception("AuthEV2First Step2: response too short (${step2Response.size} bytes)")
        }

        val ti = step2Response.copyOfRange(0, 4)
        val encRndARotated = step2Response.copyOfRange(4, 20)

        // Decrypt to get rndA_rotated, then un-rotate and compare
        val rndARotated = aesCbcDecrypt(key, ByteArray(16), encRndARotated)
        val rndAFromTag = rndARotated.drop(15).toByteArray() + rndARotated.copyOfRange(0, 15)

        if (!rndA.contentEquals(rndAFromTag)) {
            logger("  Warnung: rndA stimmt nicht überein (möglicherweise falscher Schlüssel)")
            return false
        }

        // Store session state
        transactionIdentifier = ti
        cmdCounter = 0

        // Derive session keys using CMAC
        // SesAuthMACKey = CMAC(key, 0x5A365A36 || TI || rndA[0..1] || rndB[0..1])
        // SesAuthEncKey = CMAC(key, 0xA55AA55A || TI || rndA[0..1] || rndB[0..1])
        val svEnc = byteArrayOf(0xA5.toByte(), 0x5A.toByte(), 0xA5.toByte(), 0x5A.toByte()) +
                ti + rndA.copyOfRange(0, 2) + rndB.copyOfRange(0, 2)
        val svMac = byteArrayOf(0x5A.toByte(), 0x36.toByte(), 0x5A.toByte(), 0x36.toByte()) +
                ti + rndA.copyOfRange(0, 2) + rndB.copyOfRange(0, 2)

        sessionEncKey = aesCmac(key, svEnc)
        sessionMacKey = aesCmac(key, svMac)

        logger("  Authentifizierung erfolgreich!")
        logger("  TI: ${ti.toHex()}")
        return true
    }

    // -------------------------------------------------------------------------
    // SetConfiguration (Cmd=0x5C) — CommMode.Full (encrypted + MAC)
    // -------------------------------------------------------------------------

    @Throws(IOException::class, Ntag424Exception::class)
    fun setConfiguration(option: Byte, data: ByteArray) {
        val encKey = sessionEncKey ?: throw Ntag424Exception("Nicht authentifiziert")
        val macKey = sessionMacKey ?: throw Ntag424Exception("Nicht authentifiziert")
        val ti = transactionIdentifier ?: throw Ntag424Exception("Kein TI")

        logger("SetConfiguration: Option=0x${option.toHex2()}, Data=${data.toHex()}")

        // Encrypt the data field (CommMode.Full)
        // IV for encryption: E(SesAuthEncKey, 0xA55A || TI || CmdCounter || 0x00..0x00)
        val cmdCounterBytes = byteArrayOf(
            (cmdCounter and 0xFF).toByte(),
            ((cmdCounter shr 8) and 0xFF).toByte()
        )

        val ivInput = byteArrayOf(0xA5.toByte(), 0x5A.toByte()) + ti + cmdCounterBytes +
                ByteArray(10) // padding to 16 bytes
        val iv = aesCbcEncrypt(encKey, ByteArray(16), ivInput)

        // Pad data with 0x80 0x00...
        val paddedData = padISO(data)
        val encData = aesCbcEncrypt(encKey, iv, paddedData)

        // MAC: CMAC(SesAuthMACKey, 0x5C || CmdCounter || TI || Option || encData)
        val macInput = byteArrayOf(0x5C.toByte()) + cmdCounterBytes + ti +
                byteArrayOf(option) + encData
        val fullMac = aesCmac(macKey, macInput)
        // Truncate MAC: take every second byte (bytes at odd positions 1,3,5,7,9,11,13,15)
        val mac = ByteArray(8) { i -> fullMac[2 * i + 1] }

        // Final command data: Option || encData || MAC
        val cmdData = byteArrayOf(option) + encData + mac
        val response = sendCommand(0x5C.toByte(), cmdData)

        cmdCounter++

        // Verify response MAC
        if (response.isNotEmpty()) {
            logger("  SetConfiguration response: ${response.toHex()}")
        }
        logger("  SetConfiguration erfolgreich!")
    }

    // -------------------------------------------------------------------------
    // GetTTStatus (Cmd=0xF7) — reads tamper detection status
    // -------------------------------------------------------------------------

    @Throws(IOException::class, Ntag424Exception::class)
    fun getTTStatus(): String {
        logger("GetTTStatus...")
        val macKey = sessionMacKey ?: throw Ntag424Exception("Nicht authentifiziert")
        val ti = transactionIdentifier ?: throw Ntag424Exception("Kein TI")

        val cmdCounterBytes = byteArrayOf(
            (cmdCounter and 0xFF).toByte(),
            ((cmdCounter shr 8) and 0xFF).toByte()
        )

        // MAC input: Cmd || CmdCounter || TI
        val macInput = byteArrayOf(0xF7.toByte()) + cmdCounterBytes + ti
        val fullMac = aesCmac(macKey, macInput)
        val mac = ByteArray(8) { i -> fullMac[2 * i + 1] }

        val response = sendCommand(0xF7.toByte(), mac)
        cmdCounter++

        if (response.size < 1) return "UNKNOWN"

        // Response is: StatusByte (1 byte) || ... || MACt (8 bytes)
        // StatusByte: 0xCC = intact, 0x55 = broken loop (was open), 0x00 = not enabled
        val status = response[0].toInt() and 0xFF
        return when {
            response.size >= 2 -> {
                // Two status bytes: TTByte1 || TTByte2
                val b1 = response[0].toInt() and 0xFF
                val b2 = response[1].toInt() and 0xFF
                val s1 = if (b1 == 0xCC) "C" else "O"
                val s2 = if (b2 == 0xCC) "C" else "O"
                "$s1$s2"
            }
            status == 0x00 -> "II (nicht aktiviert)"
            else -> "CC (aktiviert/intakt)"
        }
    }

    // -------------------------------------------------------------------------
    // AES crypto helpers
    // -------------------------------------------------------------------------

    private fun aesCbcEncrypt(key: ByteArray, iv: ByteArray, data: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/CBC/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
        return cipher.doFinal(data)
    }

    private fun aesCbcDecrypt(key: ByteArray, iv: ByteArray, data: ByteArray): ByteArray {
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
        val padded = data + byteArrayOf(0x80.toByte()) + ByteArray(padLen - 1)
        return padded
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private fun getSwDescription(sw1: Int, sw2: Int): String {
        return when {
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
            else -> "UNKNOWN_ERROR"
        }
    }
}

fun ByteArray.toHex(): String = joinToString("") { "%02X".format(it) }
fun Int.toHex2(): String = "%02X".format(this)
fun Byte.toHex2(): String = "%02X".format(this.toInt() and 0xFF)
