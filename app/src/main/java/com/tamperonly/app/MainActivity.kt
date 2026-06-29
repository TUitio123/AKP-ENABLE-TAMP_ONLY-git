package com.tamperonly.app

import android.app.PendingIntent
import android.content.Intent
import android.content.IntentFilter
import android.nfc.NfcAdapter
import android.nfc.NfcManager
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import java.io.IOException

class MainActivity : AppCompatActivity() {

    private var nfcAdapter: NfcAdapter? = null
    private var pendingIntent: PendingIntent? = null

    private lateinit var tvStatus: TextView
    private lateinit var tvLog: TextView
    private lateinit var btnClear: Button
    private lateinit var progressBar: ProgressBar
    private lateinit var scrollView: ScrollView
    private lateinit var layoutNfcHint: LinearLayout

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // Bind views
        tvStatus      = findViewById(R.id.tvStatus)
        tvLog         = findViewById(R.id.tvLog)
        btnClear      = findViewById(R.id.btnClear)
        progressBar   = findViewById(R.id.progressBar)
        scrollView    = findViewById(R.id.scrollView)
        layoutNfcHint = findViewById(R.id.tvNfcHint)

        // Get NFC adapter (modern API, no deprecated getDefaultAdapter)
        val nfcManager = getSystemService(NFC_SERVICE) as NfcManager
        nfcAdapter = nfcManager.defaultAdapter

        if (nfcAdapter == null) {
            setStatus("Dieses Gerät unterstützt kein NFC!", false)
            layoutNfcHint.visibility = View.GONE
            return
        }

        if (!nfcAdapter!!.isEnabled) {
            setStatus("Bitte NFC in den Einstellungen aktivieren!", false)
        } else {
            setStatus("Bereit — Chip ans Handy halten", true)
        }

        // Foreground dispatch: intercept NFC intents while app is open
        pendingIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, javaClass).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_MUTABLE
        )

        btnClear.setOnClickListener { tvLog.text = "" }

        log("App bereit. Warte auf NTAG 424 DNA TT Chip...")
        log("─────────────────────────────")
        log("NUR Tamper-Erkennung wird aktiviert.")
        log("Schlüssel werden NICHT geändert.")
        log("Nutzt Werksschlüssel (16× 0x00).")
        log("─────────────────────────────")
    }

    override fun onResume() {
        super.onResume()
        val filters = arrayOf(
            IntentFilter(NfcAdapter.ACTION_TECH_DISCOVERED),
            IntentFilter(NfcAdapter.ACTION_TAG_DISCOVERED)
        )
        val techList = arrayOf(arrayOf(IsoDep::class.java.name))
        nfcAdapter?.enableForegroundDispatch(this, pendingIntent, filters, techList)

        // Re-check NFC state when resuming (user might have enabled it)
        if (nfcAdapter != null && nfcAdapter!!.isEnabled) {
            setStatus("Bereit — Chip ans Handy halten", true)
        }
    }

    override fun onPause() {
        super.onPause()
        nfcAdapter?.disableForegroundDispatch(this)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        val action = intent.action
        if (action == NfcAdapter.ACTION_TECH_DISCOVERED || action == NfcAdapter.ACTION_TAG_DISCOVERED) {
            @Suppress("DEPRECATION")
            val tag: Tag? = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG)
            if (tag != null) handleTag(tag)
        }
    }

    private fun handleTag(tag: Tag) {
        val isoDep = IsoDep.get(tag)
        if (isoDep == null) {
            setStatus("Kein NTAG 424 DNA TT erkannt!", false)
            log("Fehler: Chip unterstützt kein IsoDep.")
            return
        }

        progressBar.visibility = View.VISIBLE
        layoutNfcHint.visibility = View.GONE
        setStatus("Chip erkannt — aktiviere Tamper...", true)
        log("\n─── Chip erkannt ───")

        Thread {
            try {
                isoDep.connect()
                isoDep.timeout = 5000

                val comm = Ntag424Communicator(isoDep) { msg -> runOnUiThread { log(msg) } }
                val result = TamperOnlyEnabler(comm) { msg -> runOnUiThread { log(msg) } }
                    .enableTamperDetection()

                runOnUiThread {
                    progressBar.visibility = View.GONE
                    layoutNfcHint.visibility = View.VISIBLE
                    if (result.success) {
                        setStatus("✓ Tamper-Erkennung aktiviert!", true)
                        log("\n✓ ERFOLG: ${result.message}")
                    } else {
                        setStatus("✗ ${result.message}", false)
                        log("\n✗ FEHLER: ${result.message}")
                    }
                    scrollView.post { scrollView.fullScroll(View.FOCUS_DOWN) }
                }
            } catch (e: IOException) {
                runOnUiThread {
                    progressBar.visibility = View.GONE
                    layoutNfcHint.visibility = View.VISIBLE
                    setStatus("Verbindung verloren — Chip länger halten!", false)
                    log("IO-Fehler: ${e.message}")
                    scrollView.post { scrollView.fullScroll(View.FOCUS_DOWN) }
                }
            } catch (e: Exception) {
                runOnUiThread {
                    progressBar.visibility = View.GONE
                    layoutNfcHint.visibility = View.VISIBLE
                    setStatus("Fehler: ${e.message}", false)
                    log("Fehler: ${e.message}")
                    scrollView.post { scrollView.fullScroll(View.FOCUS_DOWN) }
                }
            } finally {
                try { isoDep.close() } catch (_: Exception) {}
            }
        }.start()
    }

    private fun setStatus(message: String, ok: Boolean) {
        tvStatus.text = message
        tvStatus.setTextColor(
            ContextCompat.getColor(this, if (ok) R.color.status_ok else R.color.status_error)
        )
    }

    private fun log(msg: String) {
        tvLog.append("$msg\n")
        scrollView.post { scrollView.fullScroll(View.FOCUS_DOWN) }
    }
}
