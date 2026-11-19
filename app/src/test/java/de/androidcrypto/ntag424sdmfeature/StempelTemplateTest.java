package de.androidcrypto.ntag424sdmfeature;

import static org.junit.Assert.assertEquals;

import net.bplearning.ntag424.sdm.NdefTemplateMaster;
import net.bplearning.ntag424.sdm.SDMSettings;

import org.junit.Test;

import java.nio.charset.StandardCharsets;

// Makes sure that the offsets point to the values of uid, ctr and cmac, and that the MAC input is empty.
public class StempelTemplateTest {
    @Test
    public void offsetsPointToTheValues() {
        SDMSettings sdm = new SDMSettings();
        byte[] ndef = new NdefTemplateMaster().generateNdefTemplateFromUrlString(
                "https://stempel.example/station/abcdefghijklmno?uid={UID}&ctr={COUNTER}&cmac={MAC}", sdm);
        String file = new String(ndef, StandardCharsets.ISO_8859_1);
        assertEquals(file.indexOf("uid=") + 4, sdm.sdmUidOffset);
        assertEquals(file.indexOf("ctr=") + 4, sdm.sdmReadCounterOffset);
        assertEquals(file.indexOf("cmac=") + 5, sdm.sdmMacOffset);
        assertEquals(sdm.sdmMacOffset, sdm.sdmMacInputOffset);
        assertEquals("https://stempel.example/station/abcdefghijklmno?uid=**************&ctr=******&cmac=****************",
                file.substring(file.indexOf("https://")));
    }
}
