/*
Copyright (C) 2023 CYS4 Srl
See the file 'LICENSE' for copying permission
*/
package com.cys4.sensitivediscoverer.model;

import java.util.EnumSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
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
    private final String refinerRegex;
    private final transient Pattern refinerRegexCompiled;
    private final String description;
    private final EnumSet<HttpSection> sections;
    private final List<String> tests;
    private boolean active;

    public RegexEntity(String description, String regex) throws IllegalArgumentException {
        this(description, regex, true, HttpSection.getDefault(), null, null);
    }

    public RegexEntity(String description, String regex, boolean active) throws IllegalArgumentException {
        this(description, regex, active, HttpSection.getDefault(), null, null);
    }

    public RegexEntity(String description, String regex, boolean active, EnumSet<HttpSection> sections) {
        this(description, regex, active, sections, null, null);
    }

    public RegexEntity(String description, String regex, boolean active, String refinerRegex) {
        this(description, regex, active, HttpSection.getDefault(), refinerRegex, null);
    }

    public RegexEntity(String description, String regex, boolean active, EnumSet<HttpSection> sections, String refinerRegex) {
        this(description, regex, active, sections, refinerRegex, null);
    }

    public RegexEntity(String description, String regex, boolean active, EnumSet<HttpSection> sections, String refinerRegex, List<String> tests) {
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
        if (Objects.isNull(refinerRegex) || refinerRegex.isBlank()) {
            this.refinerRegex = null;
            this.refinerRegexCompiled = null;
        } else {
            this.refinerRegex = refinerRegex.endsWith("$") ? refinerRegex : refinerRegex + "$";
            this.refinerRegexCompiled = Pattern.compile(this.refinerRegex);
        }
        this.sections = sections;
        this.tests = tests;
    }

    public RegexEntity(RegexEntity entity) throws IllegalArgumentException {
        this(entity.getDescription(), entity.getRegex(), entity.isActive(), entity.getSections(), entity.getRefinerRegex().orElse(null), entity.getTests());
    }

    /**
     * Checks if the input is in the format: `"Description","Regex","Sections"`
     * Matches also if sections are not present, in this case group(3) is null
     *
     * @param input Text string to check against the format
     * @return If the input was in the correct format, a Matcher object where group(1) = description, group(2) = regex, group(3) = sections
     */
    public static Matcher checkRegexEntityFromCSV(String input) {
        return Pattern
                .compile("^[\t ]*[\"'](.+?)[\"'][\t ]*,[\t ]*[\"'](.+?)[\"'][\t ]*(?:,[\t ]*[\"'](.+?)[\"'][\t ]*)?$")
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

    public Optional<String> getRefinerRegex() {
        return Optional.ofNullable(refinerRegex);
    }

    public Optional<Pattern> getRefinerRegexCompiled() {
        return Optional.ofNullable(refinerRegexCompiled);
    }

    public String getDescription() {
        return this.description;
    }

    public EnumSet<HttpSection> getSections() {
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
        RegexEntity entity = (RegexEntity) o;
        return Objects.equals(getRegex(), entity.getRegex()) &&
                Objects.equals(getRefinerRegex(), entity.getRefinerRegex()) &&
                Objects.equals(getDescription(), entity.getDescription()) &&
                Objects.equals(getSections(), entity.getSections());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getRegex(), getRefinerRegex(), getDescription(), getSections());
    }

    @Override
    public String toString() {
        return "RegexEntity{" +
                "regex='" + getRegex() + '\'' +
                ", refinerRegex='" + getRefinerRegex().orElse("") + '\'' +
                ", description='" + getDescription() + '\'' +
                ", sections=" + getSectionsHumanReadable() +
                '}';
    }
}
