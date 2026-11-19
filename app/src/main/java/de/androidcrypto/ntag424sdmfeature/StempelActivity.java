package de.androidcrypto.ntag424sdmfeature;

import static net.bplearning.ntag424.constants.Ntag424.FACTORY_KEY;
import static net.bplearning.ntag424.constants.Ntag424.NDEF_FILE_NUMBER;
import static net.bplearning.ntag424.constants.Permissions.ACCESS_EVERYONE;
import static net.bplearning.ntag424.constants.Permissions.ACCESS_KEY0;
import static net.bplearning.ntag424.constants.Permissions.ACCESS_KEY1;
import static net.bplearning.ntag424.constants.Permissions.ACCESS_NONE;

import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.Bundle;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import net.bplearning.ntag424.DnaCommunicator;
import net.bplearning.ntag424.command.ChangeFileSettings;
import net.bplearning.ntag424.command.ChangeKey;
import net.bplearning.ntag424.command.FileSettings;
import net.bplearning.ntag424.command.GetFileSettings;
import net.bplearning.ntag424.command.GetKeyVersion;
import net.bplearning.ntag424.command.WriteData;
import net.bplearning.ntag424.encryptionmode.AESEncryptionMode;
import net.bplearning.ntag424.sdm.NdefTemplateMaster;
import net.bplearning.ntag424.sdm.SDMSettings;

/**
 * Sets up an NTAG 424 DNA tag for a station of stempel (see docs/running-an-event.md in stempel):
 * the URL with plain UID and read counter, the CMAC from key 1 (the tag key), and write access only with key 0.
 * You can do this again on the same tag. Then it writes the URL and the settings again.
 */
public class StempelActivity extends AppCompatActivity implements NfcAdapter.ReaderCallback {

    private static final String HEX_KEY = "[0-9a-fA-F]{32}";
    private EditText url, tagKey, masterKey;
    private TextView log;
    private NfcAdapter nfc;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(48, 160, 48, 48);
        url = field(root, "NFC-URL (aus NFC-Tag-Daten)");
        tagKey = field(root, "NFC-Schlüssel (32 Zeichen)");
        masterKey = field(root, "Master-Key (leer: Key 0 bleibt Werksschlüssel)");
        log = new TextView(this);
        log.setTextSize(18);
        log.setText("Felder ausfüllen, dann Tag an die Rückseite halten, bis „Fertig“ steht.");
        root.addView(log);
        ScrollView scroll = new ScrollView(this);
        scroll.addView(root);
        setContentView(scroll);
        nfc = NfcAdapter.getDefaultAdapter(this);
        if (nfc == null) log.setText("Dieses Handy hat kein NFC.");
    }

    private EditText field(LinearLayout root, String hint) {
        EditText e = new EditText(this);
        e.setHint(hint);
        e.setSingleLine();
        root.addView(e);
        return e;
    }

    private void show(String message) {
        runOnUiThread(() -> log.setText(message));
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (nfc != null) nfc.enableReaderMode(this, this,
                NfcAdapter.FLAG_READER_NFC_A | NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK, null);
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (nfc != null) nfc.disableReaderMode(this);
    }

    @Override
    public void onTagDiscovered(Tag tag) {
        String u = url.getText().toString().trim();
        String k = tagKey.getText().toString().trim();
        String m = masterKey.getText().toString().trim();
        if (!u.matches("https://[^?]+/station/[a-z0-9]+(\\?.*)?")) { show("Die URL muss https://…/station/<ID> sein."); return; }
        if (!k.matches(HEX_KEY)) { show("Der NFC-Schlüssel muss 32 Zeichen (0-9, a-f) haben."); return; }
        if (!m.isEmpty() && !m.matches(HEX_KEY)) { show("Der Master-Key muss leer sein oder 32 Zeichen (0-9, a-f) haben."); return; }
        show("Schreibe … Tag nicht bewegen.");
        try (IsoDep iso = IsoDep.get(tag)) {
            iso.connect();
            DnaCommunicator dna = new DnaCommunicator();
            dna.setTransceiver(iso::transceive);
            dna.beginCommunication();

            // A new tag has the factory key 0. A tag from an earlier run can have the master key.
            byte[] master = m.isEmpty() ? FACTORY_KEY : Utils.hexStringToByteArray(m);
            boolean factory = AESEncryptionMode.authenticateEV2(dna, ACCESS_KEY0, FACTORY_KEY);
            if (!factory && !AESEncryptionMode.authenticateEV2(dna, ACCESS_KEY0, master)) {
                show("Key 0 passt nicht. Gib den Master-Key dieses Tags ein.");
                return;
            }

            SDMSettings sdm = new SDMSettings();
            sdm.sdmMetaReadPerm = ACCESS_EVERYONE; // UID and read counter in plain text
            sdm.sdmFileReadPerm = ACCESS_KEY1; // the key of the CMAC
            sdm.sdmReadCounterRetrievalPerm = ACCESS_NONE;
            // Without a "^" placeholder, the MAC input offset is the MAC offset: an empty MAC input, as the server expects.
            byte[] ndef = new NdefTemplateMaster().generateNdefTemplateFromUrlString(
                    u.replaceFirst("\\?.*", "") + "?uid={UID}&ctr={COUNTER}&cmac={MAC}", sdm);
            WriteData.run(dna, NDEF_FILE_NUMBER, ndef, 0);

            FileSettings settings = GetFileSettings.run(dna, NDEF_FILE_NUMBER);
            settings.sdmSettings = sdm;
            settings.readPerm = ACCESS_EVERYONE;
            settings.writePerm = settings.readWritePerm = settings.changePerm = ACCESS_KEY0;
            ChangeFileSettings.run(dna, NDEF_FILE_NUMBER, settings);

            // shortcut: a set key 1 stays, because a change needs the old key. To use a tag for a different station, add a field for the old key.
            String note = "";
            if (GetKeyVersion.run(dna, ACCESS_KEY1) == 0) {
                ChangeKey.run(dna, ACCESS_KEY1, FACTORY_KEY, Utils.hexStringToByteArray(k), 1);
            } else {
                note = "\nKey 1 war schon gesetzt und bleibt.";
            }
            // Key 0 last, because the change ends the session.
            if (factory && !m.isEmpty()) ChangeKey.run(dna, ACCESS_KEY0, null, master, 1);

            show("Fertig. Tag-UID " + Utils.bytesToHex(tag.getId())
                    + (m.isEmpty() ? "\nKey 0 ist noch der Werksschlüssel." : "\nKey 0 ist der Master-Key.") + note
                    + "\nJetzt mit einem anderen Handy testen.");
        } catch (Exception e) {
            show("Fehler: " + e.getMessage() + "\nTag noch einmal halten. Der Ablauf kann ohne Schaden wiederholt werden.");
        }
    }
}
