/*
Copyright (C) 2021 CYS4 Srl
See the file 'LICENSE' for copying permission
*/
package cys4.model;

import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RegexEntity {
    private Boolean active;
    private final String regular_expression;
    private transient Pattern regex_compiled;
    private final String description;

    public RegexEntity(String description, String regex) {
        this(description, regex, true);
    }

    public RegexEntity(String description, String regex, Boolean active) {
        this.active = active;
        this.regular_expression = regex;
        this.regex_compiled = null;
        this.description = description;
    }

    /**
     * Check if the regex line to be imported is in the format:
     * "Description", "Regex"
     *
     * @param line Line to check against the format
     * @return A Matcher object where group(1) = description, and group(2) = regex
     */
    public static Matcher loadRegexEntityFromCSV(String line) {
        return Pattern
                .compile("^\\s*[\"'](.*?)[\"']\\s*,\\s*[\"'](.+?)[\"']\\s*$")
                .matcher(line);
    }

    public void compileRegex() {
        if (this.regular_expression == null || this.regular_expression.equals("")) return;

        this.regex_compiled = Pattern.compile(this.getRegex());
    }

    public Boolean isActive() {
        return this.active;
    }

    public String getRegex() {
        return this.regular_expression;
    }

    public Pattern getRegexCompiled() {
        return this.regex_compiled;
    }

    public String getDescription() {
        return this.description;
    }

    public void setActive(Boolean value) {
        this.active = value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RegexEntity that = (RegexEntity) o;
        return regular_expression.equals(that.regular_expression);
    }

    @Override
    public int hashCode() {
        return Objects.hash(regular_expression);
    }
}
