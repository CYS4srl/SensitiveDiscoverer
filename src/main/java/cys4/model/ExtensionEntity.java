/*
Copyright (C) 2021 CYS4 Srl
See the file 'LICENSE' for copying permission
*/
package cys4.model;

import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class ExtensionEntity {
    private boolean active;
    private String extension;
    private transient Pattern extension_regex_compiled;
    private final String description;

    public ExtensionEntity(String description, String extension) {
        this.active = true;
        this.extension = extension;
        this.description = description;
        this.extension_regex_compiled = null;
    }

    public ExtensionEntity(String description, String extension, boolean active) {
        this.active = active;
        this.extension = extension;
        this.description = description;
        this.extension_regex_compiled = null;
    }

    public boolean isActive() {
        return active;
    }

    public void setActive(boolean value) {
        this.active = value;
    }

    public String getDescription() {
        return this.description;
    }

    public String getExtension() {
        return this.extension;
    }

    public Pattern getRegexCompiled() {
        return this.extension_regex_compiled;
    }

    public void compileRegex() {
        if (this.extension == null || this.extension.equals("")) return;

        if (this.extension.charAt(this.extension.length() - 1) != '$') {
            this.extension += '$';
        }

        this.extension_regex_compiled = Pattern.compile(this.extension);
    }

    /**
     * Check if the extension line to be imported is in the format:
     * "Description", "Regex"
     *
     * @param line Line to check against the format
     * @return A Matcher object where group(1) = description, and group(2) = regex
     */
    public static Matcher loadExtensionEntityFromCSV(String line) {
        return Pattern
                .compile("^\\s*[\"'](.*?)[\"']\\s*,\\s*[\"'](\\..+?)[\"']\\s*$")
                .matcher(line);
    }

    /**
     * Checks if the extension is in the format ".ext"
     * @param extension The extension
     * @return Whether the extension is valid or not
     */
    public static boolean isExtensionValid(String extension) {
        return Pattern
                .compile("\\..+?")
                .matcher(extension)
                .find();
    }
}