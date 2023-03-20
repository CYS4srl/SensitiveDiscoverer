/*
Copyright (C) 2021 CYS4 Srl
See the file 'LICENSE' for copying permission
*/
package cys4.model;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RegexEntity {
    private boolean active;
    private final String regex;
    private final transient Pattern regexCompiled;
    private final String description;
    private final EnumSet<ProxyItemSection> sections;

    /**
     * Used to import from CSV where there's only the description and the regex
     * @param description
     * @param regex
     * @throws IllegalArgumentException
     */
    public RegexEntity(String description, String regex) throws IllegalArgumentException {
        this(description, regex, true, ProxyItemSection.getDefault());
    }

    public RegexEntity(String description, String regex, boolean active) throws IllegalArgumentException{
        this(description, regex, active, ProxyItemSection.getDefault());
    }

    public RegexEntity(String description, String regex, boolean active, EnumSet<ProxyItemSection> sections) {
        if (regex == null || regex.isBlank())
            throw new IllegalArgumentException("Invalid regex");
        if (sections == null)
            throw new IllegalArgumentException("Invalid sections, non-null required");

        this.active = active;
        this.description = description;
        this.regex = regex;
        this.regexCompiled = Pattern.compile(regex);
        this.sections = sections;
    }

    public RegexEntity(RegexEntity entity) throws IllegalArgumentException {
        this(entity.getDescription(), entity.getRegex(), entity.isActive(), entity.getSections());
    }

    /**
     * Checks if the input is in the format: `"Description", "Regex"`
     *
     * @param input Text string to check against the format
     * @return If the input was in the correct format, a Matcher object where group(1) = description, and group(2) = regex
     */
    public static Matcher checkRegexEntityFromCSV(String input) {
        return Pattern
                .compile("^\\s*[\"'](.*?)[\"']\\s*,\\s*[\"'](.+?)[\"']\\s*$")
                .matcher(input);
    }

    public boolean isActive() {
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

    public EnumSet<ProxyItemSection> getSections() {
        return sections;
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
        return Objects.hash(this.getRegex());
    }
}
