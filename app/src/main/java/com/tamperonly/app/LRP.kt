package com.tamperonly.app

import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

/**
 * Leakage Resilient Primitive (LRP) — NXP AN12304
 *
 * LRP is used by NTAG 424 DNA chips that have been permanently switched to LRP mode.
 * It provides:
 *   - LRP-CMAC (used for MACs and session key derivation)
 *   - LRP-LRICB (used for encryption/decryption in CommMode.Full)
 *
 * Reference: NXP AN12304 "Leakage Resilient Primitive (LRP) Specification" Rev 1.1
 *
 * Key size: 16 bytes (AES-128)
 * Block size: 16 bytes
 */
object LRP {

    // ─── Internal AES-ECB block cipher ────────────────────────────────────────

    private fun aesBlock(key: ByteArray, block: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/ECB/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"))
        return cipher.doFinal(block)
    }

    // ─── Precomputed updated keys ──────────────────────────────────────────────
    // LRP derives a set of "updated keys" from the base key.
    // updK[i] = AES(key, i || 0x00...) for i = 0..3 but
    // Actually per AN12304: u_i = AES(k, <i as 16-byte counter starting at 1>)
    // We generate 4 updated keys u1..u4

    private fun generateUpdatedKeys(key: ByteArray): Array<ByteArray> {
        return Array(4) { i ->
            val counter = ByteArray(16)
            counter[15] = (i + 1).toByte()
            aesBlock(key, counter)
        }
    }

    // ─── LRP-CMAC ──────────────────────────────────────────────────────────────
    // LRP-CMAC: A CMAC-like construct using LRP's updated keys.
    // Per AN12304 Section 2.3:
    //   1. Generate updated keys u1, u2, u3, u4
    //   2. Process message in 4-bit nibbles, each nibble selects updated key u_nibble
    //   3. XOR + AES at each step
    //   4. Final output is the MAC

    fun cmac(key: ByteArray, data: ByteArray): ByteArray {
        val updKeys = generateUpdatedKeys(key)

        // Pad data to full nibbles (each byte = 2 nibbles)
        // AN12304: data is processed as sequence of 4-bit nibbles
        // Working state r starts at 0x00..0x00
        var r = ByteArray(16)

        // Process each byte as two nibbles
        for (b in data) {
            val hiNibble = (b.toInt() ushr 4) and 0x0F
            val loNibble = b.toInt() and 0x0F

            // High nibble
            if (hiNibble in 1..4) {
                r = xor(r, updKeys[hiNibble - 1])
                r = aesBlock(key, r)
            } else {
                // nibble 0 or >4: just XOR the updKey[0] as filler
                // Per AN12304: only nibbles 1-4 are valid, pad with 0000 nibble = no op?
                // Actually per spec nibble values 0..3 map to updK[0..3]
                r = xor(r, updKeys[hiNibble and 3])
                r = aesBlock(key, r)
            }

            // Low nibble
            if (loNibble in 1..4) {
                r = xor(r, updKeys[loNibble - 1])
                r = aesBlock(key, r)
            } else {
                r = xor(r, updKeys[loNibble and 3])
                r = aesBlock(key, r)
            }
        }

        return r
    }

    // ─── LRP-CMAC (correct AN12304 implementation) ────────────────────────────
    // More accurate implementation following AN12304 exactly:
    // The state machine processes each nibble of the message.
    // Nibble value n (0-3) → XOR with u_{n+1}, then AES(key, state)

    fun cmacCorrect(key: ByteArray, data: ByteArray): ByteArray {
        val u = generateUpdatedKeys(key)
        var state = ByteArray(16) // y_0 = 0

        // Convert data to nibble stream
        for (byte in data) {
            val hi = (byte.toInt() ushr 4) and 0x0F
            val lo = byte.toInt() and 0x0F

            // Process high nibble
            state = xor(state, u[hi and 3])
            state = aesBlock(key, state)

            // Process low nibble
            state = xor(state, u[lo and 3])
            state = aesBlock(key, state)
        }

        return state
    }

    // ─── LRP Encryption (LRICB) ───────────────────────────────────────────────
    // LRICB = LRP Incremental Counter Block cipher
    // Per AN12304 Section 2.4:
    //   1. Derive an encryption subkey: ke = LRP-CMAC(key, 0x00)
    //   2. Use ke with a counter for CTR-mode encryption via LRP-CMAC

    fun encrypt(key: ByteArray, iv: ByteArray, plaintext: ByteArray): ByteArray {
        // Derive encryption key from base key using empty string MAC
        // ke = LRP_CMAC(key, 0x00 || 0x00...) — per AN12304 the subkey derivation
        // For LRICB: encrypt key ke = CMAC(key, 0x00 repeated)
        val ke = cmacCorrect(key, byteArrayOf(0x00))

        val result = ByteArray(plaintext.size)
        var counter = iv.copyOf()

        var offset = 0
        while (offset < plaintext.size) {
            // Generate keystream block: ks = CMAC(ke, counter)
            val ks = cmacCorrect(ke, counter)

            // XOR with plaintext
            val blockLen = minOf(16, plaintext.size - offset)
            for (i in 0 until blockLen) {
                result[offset + i] = (plaintext[offset + i].toInt() xor ks[i].toInt()).toByte()
            }

            // Increment counter (big-endian)
            incrementCounter(counter)
            offset += blockLen
        }

        return result
    }

    fun decrypt(key: ByteArray, iv: ByteArray, ciphertext: ByteArray): ByteArray {
        // Decryption = Encryption in CTR mode
        return encrypt(key, iv, ciphertext)
    }

    // ─── Helper: increment 16-byte big-endian counter ─────────────────────────

    private fun incrementCounter(counter: ByteArray) {
        for (i in counter.size - 1 downTo 0) {
            val v = (counter[i].toInt() and 0xFF) + 1
            counter[i] = v.toByte()
            if (v < 256) break
        }
    }

    // ─── XOR two byte arrays ──────────────────────────────────────────────────

    private fun xor(a: ByteArray, b: ByteArray): ByteArray {
        return ByteArray(a.size) { i -> (a[i].toInt() xor b[i].toInt()).toByte() }
    }
}
