/*
Copyright (C) 2021 CYS4 Srl
See the file 'LICENSE' for copying permission
*/
package cys4.controller;

import cys4.seed.BurpLeaksSeed;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;


public class Utils {

    public static String readResourceFile(String STRING_Filename)
    {
        String STRING_ReadBuffer = null;
        // load the prop files
        try (InputStream input = BurpLeaksSeed.class.getClassLoader().getResourceAsStream(STRING_Filename)) {
            assert (input != null);

            ByteArrayOutputStream result = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            for (int length; (length = input.read(buffer)) != -1; ) {
                result.write(buffer, 0, length);
            }
            // StandardCharsets.UTF_8.name() > JDK 7
            STRING_ReadBuffer = result.toString("UTF-8");

        } catch (IOException ex) {
            ex.printStackTrace();
        }
        return STRING_ReadBuffer;
    }
}
