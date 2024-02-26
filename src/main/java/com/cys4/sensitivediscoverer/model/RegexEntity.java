/*
Copyright (C) 2023 CYS4 Srl
See the file 'LICENSE' for copying permission
*/
package com.cys4.sensitivediscoverer.model;

import java.util.EnumSet;
import java.util.List;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.cys4.sensitivediscoverer.Messages.getLocaleString;

/**
 * An entity for a regex that can be used in scans.
 * Once create this entity is immutable, and can only be activated/deactivated;
 */
public class RegexEntity {
    private final String regex;
    private final transient Pattern regexCompiled;
    private final String description;
    private final EnumSet<ProxyItemSection> sections;
    private final List<String> tests;
    private boolean active;
    public RegexEntity(String description, String regex) throws IllegalArgumentException {
        this(description, regex, true, ProxyItemSection.getDefault(), null);
    }

    public RegexEntity(String description, String regex, boolean active) throws IllegalArgumentException {
        this(description, regex, active, ProxyItemSection.getDefault(), null);
    }

    public RegexEntity(String description, String regex, boolean active, EnumSet<ProxyItemSection> sections) {
        this(description, regex, active, sections, null);
    }

    public RegexEntity(String description, String regex, boolean active, EnumSet<ProxyItemSection> sections, List<String> tests) {
        if (regex == null || regex.isBlank()) {
            throw new IllegalArgumentException(getLocaleString("exception-invalidRegex"));
        }
        if (sections == null) {
            throw new IllegalArgumentException(getLocaleString("exception-invalidSections"));
        }

        this.active = active;
        this.description = description;
        this.regex = regex;
        this.regexCompiled = Pattern.compile(regex);
        this.sections = sections;
        this.tests = tests;
    }

    public RegexEntity(RegexEntity entity) throws IllegalArgumentException {
        this(entity.getDescription(), entity.getRegex(), entity.isActive(), entity.getSections());
    }

    /**
     * Checks if the input is in the format: `"Description","Regex","Sections"`
     *
     * @param input Text string to check against the format
     * @return If the input was in the correct format, a Matcher object where group(1) = description, group(2) = regex, group(3) = sections
     */
    public static Matcher checkRegexEntityFromCSV(String input) {
        return Pattern
                .compile("^\\s*[\"'](.*?)[\"']\\s*,\\s*[\"'](.+?)[\"']\\s*,\\s*[\"'](.+?)[\"']\\s*$")
                .matcher(input);
    }

    public List<String> getTests() {
        return tests;
    }

    public boolean isActive() {
        return this.active;
    }

    public void setActive(boolean value) {
        this.active = value;
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

    public String getSectionsHumanReadable() {
        String reqSections = sections.toString()
                .replaceAll("Request", "")
                .replaceAll("Response\\w+(, )?", "")
                .replaceAll("(\\[]|, (?=]))", "");
        if (!reqSections.isBlank()) reqSections = "REQ" + reqSections;
        String resSections = sections.toString()
                .replaceAll("Response", "")
                .replaceAll("Request\\w+(, )?", "")
                .replaceAll("(\\[]|, (?=]))", "");
        if (!resSections.isBlank()) resSections = "RES" + resSections;
        String separator = (reqSections.isBlank() || resSections.isBlank()) ? "" : ", ";
        return String.format("%s%s%s", reqSections, separator, resSections);
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
