/*
Copyright (C) 2023 CYS4 Srl
See the file 'LICENSE' for copying permission
*/
package com.cys4.sensitivediscoverer.utils;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;


/**
 * Utils package
 */
public class Utils {

    /**
     * Read the content of a resource file.
     *
     * @param filepath Path to the resource file.
     * @return A UTF-8 string with the content of the file read.
     */
    public static String readResourceFile(String filepath) {
        try {
            InputStream inputStream = Utils.getResourceAsStream(filepath);
            if (Objects.isNull(inputStream)) return null;

            InputStreamReader isr = new InputStreamReader(inputStream, StandardCharsets.UTF_8);
            BufferedReader reader = new BufferedReader(isr);

            return reader.lines().collect(Collectors.joining(System.lineSeparator()));
        } catch (Exception ex) {
            ex.printStackTrace();
            return null;
        }
    }

    public static Properties loadConfigFile() throws Exception {
        Properties properties;

        InputStream input = Utils.getResourceAsStream("config.properties");
        properties = new Properties();
        properties.load(input);
        return properties;
    }

    public static String getExtensionVersion() {
        return Utils.class.getPackage().getImplementationVersion();
    }

    /**
     * Returns an input stream for reading the specified resource.
     *
     * @param name The resource name
     * @return An input stream for reading the resource; null if the resource could not be found or there was an error.
     */
    public static InputStream getResourceAsStream(String name) {
        return Utils.class.getClassLoader().getResourceAsStream(name);
    }

}
