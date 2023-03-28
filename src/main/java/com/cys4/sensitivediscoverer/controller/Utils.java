/*
Copyright (C) 2021 CYS4 Srl
See the file 'LICENSE' for copying permission
*/
package com.cys4.sensitivediscoverer.controller;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.stream.Collectors;


/**
 * Utils package
 */
public class Utils {

    /**
     * Read the content of a resource file.
     * @param filepath Path to the resource file.
     * @return A UTF-8 string with the content of the file read.
     */
    public static String readResourceFile(String filepath)
    {
        try {
            InputStream inputStream = Utils.class.getClassLoader().getResourceAsStream(filepath);
            if (Objects.isNull(inputStream)) return null;

            InputStreamReader isr = new InputStreamReader(inputStream, StandardCharsets.UTF_8);
            BufferedReader reader = new BufferedReader(isr);

            return reader.lines().collect(Collectors.joining(System.lineSeparator()));
        } catch (Exception ex) {
            ex.printStackTrace();
            return null;
        }
    }
}
