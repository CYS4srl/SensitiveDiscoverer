/*
Copyright (C) 2023 CYS4 Srl
See the file 'LICENSE' for copying permission
*/
package com.cys4.sensitivediscoverer.model;

import java.util.EnumSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.MatchResult;
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

    public RegexEntity(String description, String regex, boolean active, EnumSet<HttpSection> sections, String refinerRegex) {
        this(description, regex, active, sections, refinerRegex, null);
    }

    /**
     * @param description
     * @param regex
     * @param active
     * @param sections
     * @param refinerRegex regex to refine the match. It is used only after the main regex matches, and it's applied to
     *                     a defined range before the match. This regex always ends with a "$" (dollar sign) to ensure
     *                     the result can be prepended to the match. If the final "$" is missing, it's added automatically.
     * @param tests
     */
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
     * Tries to match the CSV line as a RegexEntity.
     * <br><br>
     * There are 2 supported formats:
     * <ul><li>the extended: {@code "...","...","...","..."}</li><li>the simple: {@code "...","..."}</li></ul>
     *
     * @param input CSV line to match against one of the formats
     * @return An Optional that may contain the successful result of the match. When there's a result, it always has 4 groups but the 3rd and 4th are null when the simple format is matched.
     */
    public static Optional<MatchResult> checkRegexEntityFromCSV(String input) {
        return Pattern
                .compile("^\"(.+?)\",\"(.+?)\"(?:,\"(.*?)\",\"(.*?)\")?$")
                .matcher(input)
                .results()
                .findFirst();
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
