/*
Copyright (C) 2021 CYS4 Srl
See the file 'LICENSE' for copying permission
*/
package cys4.model;

import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class ExtensionEntity {
    private Boolean active;
    private final String extension;
    private final String description;

    public ExtensionEntity(String description, String extension) {
        this.active = true;
        this.extension = extension;
        this.description = description;
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

    //
    //  function to check if the extensions added are in the form of <Description,.Extension>
    //
    public static boolean extIsInCorrectFormat(String lineWithRegex) {
        String regex = "^[\"|'].*[\"|'],(\\s)?[\"|'](^)?\\..+[\"|']$";
        Pattern regex_pattern = Pattern.compile(regex);
        Matcher regex_matcher = regex_pattern.matcher(lineWithRegex);
        return regex_matcher.find();
    }
}