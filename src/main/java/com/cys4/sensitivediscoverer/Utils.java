/*
Copyright (C) 2023 CYS4 Srl
See the file 'LICENSE' for copying permission
*/
package com.cys4.sensitivediscoverer;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import static com.cys4.sensitivediscoverer.Messages.getLocaleString;


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
     *
     * @param extensionName the extension of the saved file
     * @param lines         The lines to write in the file
     */
    public static void saveToFile(String extensionName, List<String> lines) {
        JFrame parentFrame = new JFrame();
        JFileChooser fileChooser = new JFileChooser();
        FileNameExtensionFilter filter = new FileNameExtensionFilter("." + extensionName, extensionName);
        fileChooser.setFileFilter(filter);
        fileChooser.setDialogTitle(getLocaleString("utils-saveToFile-exportFile"));

        int userSelection = fileChooser.showSaveDialog(parentFrame);
        if (userSelection != JFileChooser.APPROVE_OPTION) return;

        String exportFilePath = fileChooser.getSelectedFile().getAbsolutePath();
        if (!exportFilePath.endsWith("." + extensionName)) {
            exportFilePath += "." + extensionName;
        }

        try {
            PrintWriter pwt = new PrintWriter(exportFilePath, StandardCharsets.UTF_8);
            lines.forEach(pwt::println);
            pwt.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Open JFileChooser to get lines from a file
     *
     * @param extensionName the extension to filter files
     * @return The lines from the file, or null if there was an error
     */
    public static List<String> linesFromFile(String extensionName) {
        JFrame parentFrame = new JFrame();
        JFileChooser fileChooser = new JFileChooser();
        FileNameExtensionFilter filter = new FileNameExtensionFilter("." + extensionName, extensionName);
        fileChooser.setFileFilter(filter);
        fileChooser.setDialogTitle(getLocaleString("utils-linesFromFile-importFile"));

        int userSelection = fileChooser.showOpenDialog(parentFrame);
        if (userSelection != JFileChooser.APPROVE_OPTION) return null;

        File selectedFile = fileChooser.getSelectedFile();
        try {
            return Files.readAllLines(selectedFile.toPath());
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Recursively disable all components that have a certain property set.
     * When a component with the property specified is found, the component and all the recursive children are enabled to the state specified.
     *
     * @param component parent component
     * @param enabled   enabled state to set
     */
    public static void setEnabledRecursiveComponentsWithProperty(Component component, boolean enabled, String propertyName) {
        // if component has the property, stop searching this branch and disable everything
        if (component instanceof JComponent jComponent && Objects.nonNull(jComponent.getClientProperty(propertyName))) {
            setEnabledRecursive(component, enabled);
            return;
        }

        // otherwise, continue the search on the children
        if (component instanceof Container container) {
            for (Component child : container.getComponents()) {
                setEnabledRecursiveComponentsWithProperty(child, enabled, propertyName);
            }
        }
    }

    private static void setEnabledRecursive(Component component, boolean enabled) {
        boolean newState = enabled;

        if (component instanceof JComponent jComponent) {
            if (component.isEnabled() == enabled) {
                // if component is already in the required state, save this information in case the operation needs to be reversed
                jComponent.putClientProperty("previouslyEnabled", enabled);
            } else {
                // set the state to the previous if present, otherwise use the passed one
                Object previousState = jComponent.getClientProperty("previouslyEnabled");
                jComponent.putClientProperty("previouslyEnabled", null);
                newState = (Objects.nonNull(previousState)) ? (boolean) previousState : enabled;
            }
        }

        component.setEnabled(newState);

        if (component instanceof Container container) {
            for (Component child : container.getComponents()) {
                setEnabledRecursive(child, enabled);
            }
        }
    }
}
