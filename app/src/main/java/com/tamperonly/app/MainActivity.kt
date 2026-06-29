package com.tamperonly.app

import android.app.PendingIntent
import android.content.Intent
import android.content.IntentFilter
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import java.io.IOException

/**
 * 424DNA TT Tamper-Enable App
 *
 * Purpose: ONLY activates the Tamper Detection feature on NXP NTAG 424 DNA TT chips.
 * - Does NOT change any keys
 * - Does NOT change NDEF content
 * - Does NOT change any other settings
 * - Only sends SetConfiguration Option 07h to enable tamper detection
 *
 * The SetConfiguration command requires authentication with AppMasterKey (Key 0).
 * This app uses the FACTORY default key (all zeros) for authentication.
 * If your chip already has a custom AppMasterKey, this app cannot enable tamper detection.
 */
class MainActivity : AppCompatActivity() {

    private var nfcAdapter: NfcAdapter? = null
    private var pendingIntent: PendingIntent? = null
    private var intentFilters: Array<IntentFilter>? = null
    private var techList: Array<Array<String>>? = null

    private lateinit var tvStatus: TextView
    private lateinit var tvLog: TextView
    private lateinit var btnClear: Button
    private lateinit var progressBar: ProgressBar
    private lateinit var scrollView: ScrollView
    private lateinit var tvNfcHint: TextView

    private var isWaitingForTag = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        tvStatus = findViewById(R.id.tvStatus)
        tvLog = findViewById(R.id.tvLog)
        btnClear = findViewById(R.id.btnClear)
        progressBar = findViewById(R.id.progressBar)
        scrollView = findViewById(R.id.scrollView)
        tvNfcHint = findViewById(R.id.tvNfcHint)

        nfcAdapter = NfcAdapter.getDefaultAdapter(this)

        if (nfcAdapter == null) {
            setStatus("Fehler: Dieses Gerät unterstützt kein NFC!", false)
            return
        }

        if (!nfcAdapter!!.isEnabled) {
            setStatus("Bitte NFC in den Einstellungen aktivieren!", false)
        }

        // Set up foreground dispatch for NFC
        pendingIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, javaClass).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_MUTABLE
        )

        val ndefFilter = IntentFilter(NfcAdapter.ACTION_TECH_DISCOVERED)
        intentFilters = arrayOf(ndefFilter)
        techList = arrayOf(arrayOf(IsoDep::class.java.name))

        btnClear.setOnClickListener {
            tvLog.text = ""
        }

        isWaitingForTag = true
        setStatus("Bereit — halte den NTAG 424 DNA TT Chip ans Telefon", true)
        log("App gestartet. Warte auf NFC-Chip...")
        log("WICHTIG: Nur Tamper-Erkennung wird aktiviert.")
        log("Schlüssel werden NICHT geändert.")
        log("Nutzt Standard-Werksschlüssel (alle Nullen).")
    }

    override fun onResume() {
        super.onResume()
        nfcAdapter?.enableForegroundDispatch(this, pendingIntent, intentFilters, techList)
    }

    override fun onPause() {
        super.onPause()
        nfcAdapter?.disableForegroundDispatch(this)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        if (NfcAdapter.ACTION_TECH_DISCOVERED == intent.action ||
            NfcAdapter.ACTION_TAG_DISCOVERED == intent.action
        ) {
            val tag: Tag? = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG)
            if (tag != null) {
                handleTag(tag)
            }
        }
    }

    private fun handleTag(tag: Tag) {
        val isoDep = IsoDep.get(tag)
        if (isoDep == null) {
            log("Fehler: Kein IsoDep-Chip erkannt. Kein NTAG 424 DNA TT?")
            setStatus("Kein NTAG 424 DNA TT erkannt!", false)
            return
        }

        progressBar.visibility = View.VISIBLE
        setStatus("Chip erkannt — Tamper-Erkennung wird aktiviert...", true)
        log("\n--- Neuer Chip erkannt ---")

        Thread {
            try {
                isoDep.connect()
                isoDep.timeout = 3000

                val communicator = Ntag424Communicator(isoDep) { msg -> runOnUiThread { log(msg) } }
                val tamperEnabler = TamperOnlyEnabler(communicator) { msg -> runOnUiThread { log(msg) } }
                val result = tamperEnabler.enableTamperDetection()

                runOnUiThread {
                    progressBar.visibility = View.GONE
                    if (result.success) {
                        setStatus("✓ Tamper-Erkennung erfolgreich aktiviert!", true)
                        log("\n✓ ERFOLG: Tamper-Erkennung wurde aktiviert.")
                        log("  Status: ${result.message}")
                    } else {
                        setStatus("✗ Fehler: ${result.message}", false)
                        log("\n✗ FEHLER: ${result.message}")
                    }
                    scrollView.post { scrollView.fullScroll(View.FOCUS_DOWN) }
                }
            } catch (e: IOException) {
                runOnUiThread {
                    progressBar.visibility = View.GONE
                    setStatus("Verbindungsfehler — Chip zu früh entfernt?", false)
                    log("Verbindungsfehler: ${e.message}")
                    scrollView.post { scrollView.fullScroll(View.FOCUS_DOWN) }
                }
            } catch (e: Exception) {
                runOnUiThread {
                    progressBar.visibility = View.GONE
                    setStatus("Fehler: ${e.message}", false)
                    log("Unerwarteter Fehler: ${e.message}")
                    scrollView.post { scrollView.fullScroll(View.FOCUS_DOWN) }
                }
            } finally {
                try { isoDep.close() } catch (_: Exception) {}
            }
        }.start()
    }

    private fun setStatus(message: String, success: Boolean) {
        tvStatus.text = message
        tvStatus.setTextColor(
            ContextCompat.getColor(
                this,
                if (success) R.color.status_ok else R.color.status_error
            )
        )
    }

    private fun log(message: String) {
        tvLog.append("$message\n")
        scrollView.post { scrollView.fullScroll(View.FOCUS_DOWN) }
    }
}
