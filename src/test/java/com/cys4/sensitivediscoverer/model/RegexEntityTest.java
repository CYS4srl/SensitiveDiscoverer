package com.cys4.sensitivediscoverer.model;

import org.junit.jupiter.api.Test;

import java.util.EnumSet;
import java.util.Optional;
import java.util.regex.MatchResult;

import static org.assertj.core.api.Assertions.*;

class RegexEntityTest {

    @Test
    void testInvalidRegexConstructor() {
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> new RegexEntity("desc", ""));
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> new RegexEntity("desc", null));
        assertThatNoException()
                .isThrownBy(() -> new RegexEntity("desc", "^regex$"));

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> new RegexEntity("desc", "", false));
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> new RegexEntity("desc", null, false));
        assertThatNoException()
                .isThrownBy(() -> new RegexEntity("desc", "^regex$", false));

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> new RegexEntity("desc", "", false, HttpSection.ALL, ""));
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> new RegexEntity("desc", null, false, HttpSection.ALL, ""));
        assertThatNoException()
                .isThrownBy(() -> new RegexEntity("desc", "^regex$", false, HttpSection.ALL, ""));
    }

    @Test
    void testInvalidSectionsConstructor() {
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> new RegexEntity("desc", "^regex$", true, null, null));
        assertThatNoException()
                .isThrownBy(() -> new RegexEntity("desc", "^regex$", true, EnumSet.of(HttpSection.RES_BODY, HttpSection.REQ_BODY), null));
    }

    @Test
    void testDefaultRegexIsActive() {
        RegexEntity regex = new RegexEntity("desc", "regex");
        assertThat(regex.isActive()).isTrue();
    }

    @Test
    void testActiveFlag() {
        RegexEntity entity;

        entity = new RegexEntity("desc", "regex", true);
        assertThat(entity.isActive()).isTrue();
        entity.setActive(false);
        assertThat(entity.isActive()).isFalse();
        entity.setActive(true);
        assertThat(entity.isActive()).isTrue();

        entity = new RegexEntity("desc", "regex", false);
        assertThat(entity.isActive()).isFalse();
    }

    @Test
    void testCheckRegexEntityFromCSV_simpleFormat() {
        Optional<MatchResult> matchResult = RegexEntity.checkRegexEntityFromCSV("\"description\",\"^test$\"");
        assertThat(matchResult).isNotEmpty();
        MatchResult match = matchResult.get();
        assertThat(match.groupCount()).isEqualTo(4);
        assertThat(match.group(1)).isEqualTo("description");
        assertThat(match.group(2)).isEqualTo("^test$");
        assertThat(match.group(3)).isNull();
        assertThat(match.group(4)).isNull();
    }

    @Test
    void testCheckRegexEntityFromCSV_extendedFormat() {
        Optional<MatchResult> matchResult;
        MatchResult match;

        matchResult = RegexEntity.checkRegexEntityFromCSV("\"description\",\"^test$\",\"SECTION_1|SECTION_2\",\"test$\"");
        assertThat(matchResult).isNotEmpty();
        match = matchResult.get();
        assertThat(match.groupCount()).isEqualTo(4);
        assertThat(match.group(1)).isEqualTo("description");
        assertThat(match.group(2)).isEqualTo("^test$");
        assertThat(match.group(3)).isEqualTo("SECTION_1|SECTION_2");
        assertThat(match.group(4)).isEqualTo("test$");

        matchResult = RegexEntity.checkRegexEntityFromCSV("\"description\",\"^test$\",\"\",\"\"");
        assertThat(matchResult).isNotEmpty();
        match = matchResult.get();
        assertThat(match.groupCount()).isEqualTo(4);
        assertThat(match.group(1)).isEqualTo("description");
        assertThat(match.group(2)).isEqualTo("^test$");
        assertThat(match.group(3)).isEqualTo("");
        assertThat(match.group(4)).isEqualTo("");
    }

    @Test
    void testGetSectionsHumanReadable() {
        RegexEntity entity;
        EnumSet<HttpSection> sections;

        sections = HttpSection.ALL;
        entity = new RegexEntity("desc", "regex", true, sections, "");
        assertThat(entity.getSectionsHumanReadable()).isEqualTo("REQ[URL, Headers, Body], RES[Headers, Body]");

        sections = EnumSet.of(HttpSection.RES_BODY);
        entity = new RegexEntity("desc", "regex", true, sections, "");
        assertThat(entity.getSectionsHumanReadable()).isEqualTo("RES[Body]");

        sections = EnumSet.of(HttpSection.REQ_HEADERS, HttpSection.REQ_BODY);
        entity = new RegexEntity("desc", "regex", true, sections, "");
        assertThat(entity.getSectionsHumanReadable()).isEqualTo("REQ[Headers, Body]");
    }
}