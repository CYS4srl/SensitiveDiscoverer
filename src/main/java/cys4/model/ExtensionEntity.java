/*
Copyright (C) 2021 CYS4 Srl
See the file 'LICENSE' for copying permission
*/
package cys4.model;

import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class ExtensionEntity {
    private boolean active;
    private final String regex;
    private final transient Pattern regexCompiled;
    private final String description;

    public ExtensionEntity(String description, String regex) {
        this(description, regex, true);
    }

    public ExtensionEntity(String description, String regex, boolean active) throws IllegalArgumentException {
        if (regex == null || regex.isBlank())
            throw new IllegalArgumentException("Invalid regex");

        this.active = active;
        this.description = description;

        if (regex.endsWith("$")) {
            this.regex = regex;
        } else {
            this.regex = regex + '$';
        }
        this.regexCompiled = Pattern.compile(this.regex);
    }

    public ExtensionEntity(ExtensionEntity entity) throws IllegalArgumentException {
        this(entity.getDescription(), entity.getRegex(), entity.isActive());
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
                .compile("^\\s*[\"'](.*?)[\"']\\s*,\\s*[\"'](\\\\\\..+?\\$?)[\"']\\s*$")
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

    public boolean isActive() {
        return active;
    }

    public String getDescription() {
        return this.description;
    }

    public String getRegex() {
        return this.regex;
    }

    public Pattern getRegexCompiled() {
        return this.regexCompiled;
    }

    public void setActive(boolean value) {
        this.active = value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ExtensionEntity that = (ExtensionEntity) o;
        return this.getRegex().equals(that.getRegex());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getRegex());
    }
}