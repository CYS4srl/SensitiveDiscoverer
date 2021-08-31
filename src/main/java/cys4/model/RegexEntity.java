/*
Copyright (C) 2021 CYS4 Srl
See the file 'LICENSE' for copying permission
*/

package cys4.model;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RegexEntity {
    private Boolean active;
    private final String regular_expression;
    private final String description;

    public RegexEntity(String description, String regex) {
        this.active = true;
        this.regular_expression = regex;
        this.description = description;
    }

    public RegexEntity(String description, String regex, Boolean active) {
        this.active = active;
        this.regular_expression = regex;
        this.description = description;
    }

    public Boolean isActive() {
        return this.active;
    }

    public String getRegex() {
        return regular_expression;
    }

    public String getDescription() {
        return description;
    }

    public void setActive(Boolean value) {
        this.active = value;
    }

    // Overriding equals() to compare two Complex objects
    @Override
    public boolean equals(Object o) {

        // If the object is compared with itself then return true
        if (o == this) {
            return true;
        }

        /* Check if o is an instance of Complex or not
          "null instanceof [type]" also returns false */
        if (!(o instanceof RegexEntity)) {
            return false;
        }

        // Compare the data members and return accordingly
        return this.getRegex().equals(((RegexEntity) o).getRegex());
    }

    //
    //  function to check if the regexes added are in the form of <Description; Regex>
    //
    public static boolean regexIsInCorrectFormat(String lineWithRegex) {
        String regex = "^[\"|'].*[\"|'],(\\s)?[\"|'].+[\"|']$";
        Pattern regex_pattern = Pattern.compile(regex);
        Matcher regex_matcher = regex_pattern.matcher(lineWithRegex);
        return regex_matcher.find();
    }

}