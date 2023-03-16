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
    private final List<String> sectionsToMatch; //todo remove, as of now required only for GSON deserialization
    private final EnumSet<ProxyItemSection> sections;

    public RegexEntity(String description, String regex) throws IllegalArgumentException {
        this(description, regex, true, Collections.emptyList());
    }

    public RegexEntity(String description, String regex, boolean active) throws IllegalArgumentException{
        this(description, regex, active, Collections.emptyList());
    }

    public RegexEntity(String description, String regex, boolean active, List<String> sectionsToMatch) throws IllegalArgumentException {
        if (regex == null || regex.isBlank())
            throw new IllegalArgumentException("Invalid regex");

        this.active = active;
        this.description = description;

        this.regex = regex;
        this.regexCompiled = Pattern.compile(regex);

        if (sectionsToMatch.isEmpty()) {
            this.sections = ProxyItemSection.RES;
            this.sectionsToMatch = new ArrayList<>(); // String[]{}; //TODO remove this
        } else {
            this.sections = ProxyItemSection.parseSectionsToMatch(sectionsToMatch);
            this.sectionsToMatch = sectionsToMatch; // Arrays.copyOf(sectionsToMatch, sectionsToMatch.length); //TODO remove this
        }
    }

    public RegexEntity(String description, String regex, boolean active, EnumSet<ProxyItemSection> sections) {
        if (regex == null || regex.isBlank())
            throw new IllegalArgumentException("Invalid regex");

        this.active = active;
        this.description = description;

        this.regex = regex;
        this.regexCompiled = Pattern.compile(regex);

        this.sectionsToMatch = new ArrayList<>(); // String[]{}; //TODO remove this
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

    public List<String> getSectionsToMatch() {
        if (Objects.isNull(this.sectionsToMatch))
            return Collections.emptyList();
        return List.copyOf(this.sectionsToMatch);
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
