package com.virustotal.yara;


import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

public class YaraJavaTests {

    public static final int NULL_CHAR = 1;

    @BeforeAll
    public static void setup() {
    }

    @Test
    public void yaraVersionTest() {
        ByteBuffer versionBuffer = yara_h_1.YR_VERSION().asByteBuffer();
        byte[] versionBytes = new byte[versionBuffer.remaining() - NULL_CHAR];
        versionBuffer.get(versionBytes);

        String versionString = new String(versionBytes, StandardCharsets.UTF_8);

        Assertions.assertNotNull(versionString);
        Assertions.assertFalse(versionString.isEmpty());
        Assertions.assertEquals("4.1.3", versionString);
    }
}
