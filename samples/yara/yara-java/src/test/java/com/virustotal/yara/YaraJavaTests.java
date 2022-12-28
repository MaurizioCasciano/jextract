package com.virustotal.yara;


import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import static com.virustotal.yara.yara_h.ERROR_SUCCESS;
import static com.virustotal.yara.yara_h_1.*;

public class YaraJavaTests {

    public static final int NULL_CHAR = 1;

    @BeforeAll
    public static void init() {
        /*
         * https://yara.readthedocs.io/en/stable/capi.html#c.yr_initialize
         *
         * Initialize the library. Must be called by the main thread before using any other function.
         * Return ERROR_SUCCESS on success another error code in case of error.
         * The list of possible return codes vary according to the modules compiled into YARA.
         *
         * int yr_initialize(void)
         */
        int initializeResult = yr_initialize();

        Assertions.assertEquals(ERROR_SUCCESS(), initializeResult);
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

    @AfterAll
    public static void destroy() {
        /*
         * https://yara.readthedocs.io/en/stable/capi.html#c.yr_finalize
         *
         * Finalize the library. Must be called by the main free to release any resource allocated by the library.
         * Return ERROR_SUCCESS on success another error code in case of error.
         * The list of possible return codes vary according to the modules compiled into YARA.
         *
         * int yr_finalize(void)
         */
        int finalizeResult = yr_finalize();

        Assertions.assertEquals(ERROR_SUCCESS(), finalizeResult);
    }
}
