/*
Copyright (C) 2021 CYS4 Srl
See the file 'LICENSE' for copying permission
*/
package cys4.model;

import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RegexEntity {
    private boolean active;
    private final String regex;
    private transient Pattern regexCompiled;
    private final String description;

    public RegexEntity(String description, String regex) {
        this(description, regex, true);
    }

    public RegexEntity(String description, String regex, Boolean active) {
        this.active = active;
        this.regex = regex;
        this.regexCompiled = null;
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
        if (this.regex == null || this.regex.equals("")) return;

        this.regexCompiled = Pattern.compile(this.getRegex());
    }

    public Boolean isActive() {
        return this.active;
    }

    public String getRegex() {
        return this.regex;
    }

    public Pattern getRegexCompiled() {
        return this.regexCompiled;
    }

    public String getDescription() {
        return this.description;
    }

    public void setActive(boolean value) {
        this.active = value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RegexEntity that = (RegexEntity) o;
        return this.getRegex().equals(that.getRegex());
    }

    @Override
    public int hashCode() {
        return Objects.hash(regex);
    }
}
