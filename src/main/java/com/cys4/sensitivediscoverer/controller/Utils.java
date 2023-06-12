/*
Copyright (C) 2021 CYS4 Srl
See the file 'LICENSE' for copying permission
*/
package com.cys4.sensitivediscoverer.controller;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.List;
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

    /**
     * Open JFileChooser to save lines to a file
     * @param extensionName the extension of the saved file
     * @param lines The lines to write in the file
     */
    public static void saveToFile(String extensionName, List<String> lines) {
        JFrame parentFrame = new JFrame();
        JFileChooser fileChooser = new JFileChooser();
        FileNameExtensionFilter filter = new FileNameExtensionFilter("."+extensionName,extensionName);
        fileChooser.setFileFilter(filter);
        fileChooser.setDialogTitle("Specify the export file");

        int userSelection = fileChooser.showSaveDialog(parentFrame);
        if (userSelection != JFileChooser.APPROVE_OPTION) return;

        String exportFilePath = fileChooser.getSelectedFile().getAbsolutePath();
        if (!exportFilePath.endsWith("."+extensionName)) {
            exportFilePath += "."+extensionName;
        }
        try {
            PrintWriter pwt = new PrintWriter(exportFilePath);
            lines.forEach(pwt::println);
            pwt.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
    }
}
