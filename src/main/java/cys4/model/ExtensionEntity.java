/*
Copyright (C) 2021 CYS4 Srl
See the file 'LICENSE' for copying permission
*/
package cys4.model;

import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class ExtensionEntity {
    private Boolean active;
    private String extension;
    private transient Pattern extension_regex_compiled;
    private final String description;

    public ExtensionEntity(String description, String extension) {
        this.active = true;
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

    public boolean compileRegex() {
        if (this.extension == null || this.extension == "") return false;

        if (this.extension.charAt(this.extension.length() - 1) != '$') {
            this.extension += '$';
        }

        this.extension_regex_compiled = Pattern.compile(this.extension);
        return true;
    }

    /**
     * Check if the extensions added are in the form of <Description; .Extension>
     * @param lineWithRegex Line to check against the format
     * @return a boolean with wether the format is respected
     */
    public static boolean extIsInCorrectFormat(String lineWithRegex) {
        String regex = "^[\"|'].*[\"|'],(\\s)?[\"|'](^)?\\..+[\"|']$";
        Pattern regex_pattern = Pattern.compile(regex);
        Matcher regex_matcher = regex_pattern.matcher(lineWithRegex);
        return regex_matcher.find();
    }
}