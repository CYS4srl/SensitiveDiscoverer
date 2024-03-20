package com.cys4.sensitivediscoverer.model;

import org.junit.jupiter.api.Test;

import java.util.EnumSet;
import java.util.regex.Matcher;

import static org.assertj.core.api.Assertions.*;

class RegexEntityTest {

    @Test
    void testInvalidRegexConstructor() {
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> new RegexEntity("desc", ""));
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> new RegexEntity("desc", null));
        assertThatNoException().isThrownBy(() -> new RegexEntity("desc", "^regex$"));
    }

    @Test
    void testInvalidSectionsConstructor() {
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() ->
                        new RegexEntity("desc", "^regex$", true, null));
        assertThatNoException()
                .isThrownBy(() ->
                        new RegexEntity("desc", "^regex$", true, EnumSet.of(ProxyItemSection.RES_BODY, ProxyItemSection.REQ_BODY)));
    }

    @Test
    void testDefaultRegexIsActive() {
        RegexEntity entity = new RegexEntity("desc", "regex");
        assertThat(entity.isActive()).isTrue();
    }

    @Test
    void testActiveFlag() {
        RegexEntity entity;

        entity = new RegexEntity("desc", "regex", true);
        assertThat(entity.isActive()).isTrue();

        entity = new RegexEntity("desc", "regex", false);
        assertThat(entity.isActive()).isFalse();

        entity = new RegexEntity("desc", "regex", true);
        entity.setActive(false);
        assertThat(entity.isActive()).isFalse();
        entity.setActive(true);
        assertThat(entity.isActive()).isTrue();
    }

    @Test
    void checkRegexEntityFromCSVNoSections() {
        Matcher csvMatcher = RegexEntity.checkRegexEntityFromCSV("\"description\",\"regex\"");
        assertThat(csvMatcher.find()).isTrue();
        assertThat(csvMatcher.groupCount()).isEqualTo(3);
        assertThat(csvMatcher.group(1)).isEqualTo("description");
        assertThat(csvMatcher.group(2)).isEqualTo("regex");
        assertThat(csvMatcher.group(3)).isNullOrEmpty();
    }

    @Test
    void checkRegexEntityFromCSV() {
        Matcher csvMatcher = RegexEntity.checkRegexEntityFromCSV("\"description\",\"regex\",\"SECTION_1|SECTION_2\"");
        assertThat(csvMatcher.find()).isTrue();
        assertThat(csvMatcher.groupCount()).isEqualTo(3);
        assertThat(csvMatcher.group(1)).isEqualTo("description");
        assertThat(csvMatcher.group(2)).isEqualTo("regex");
        assertThat(csvMatcher.group(3)).isEqualTo("SECTION_1|SECTION_2");
    }

    @Test
    void getSectionsHumanReadable() {
        RegexEntity entity;
        EnumSet<ProxyItemSection> sections;

        sections = ProxyItemSection.ALL;
        entity = new RegexEntity("desc", "regex", true, sections);
        assertThat(entity.getSectionsHumanReadable()).isEqualTo("REQ[URL, Headers, Body], RES[Headers, Body]");

        sections = EnumSet.of(ProxyItemSection.RES_BODY);
        entity = new RegexEntity("desc", "regex", true, sections);
        assertThat(entity.getSectionsHumanReadable()).isEqualTo("RES[Body]");

        sections = EnumSet.of(ProxyItemSection.REQ_HEADERS, ProxyItemSection.REQ_BODY);
        entity = new RegexEntity("desc", "regex", true, sections);
        assertThat(entity.getSectionsHumanReadable()).isEqualTo("REQ[Headers, Body]");
    }
}