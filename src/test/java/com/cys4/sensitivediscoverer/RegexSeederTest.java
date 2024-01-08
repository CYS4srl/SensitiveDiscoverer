package com.cys4.sensitivediscoverer;

import com.cys4.sensitivediscoverer.model.RegexEntity;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class RegexSeederTest {

    @org.junit.jupiter.api.Test
    void getGeneralRegexes() {
        List<RegexEntity> regexList = RegexSeeder.getGeneralRegexes();
        assertThat(regexList)
                .isNotEmpty()
                .allSatisfy(regex -> assertThat(regex.getTests())
                        .as("%s", regex.getDescription())
                        .isNotEmpty()
                        .allSatisfy(s -> assertThat(s)
                                .isNotEmpty()
                                .containsPattern(regex.getRegexCompiled())));
    }

    @org.junit.jupiter.api.Test
    void getExtensionRegexes() {
        List<RegexEntity> regexList = RegexSeeder.getExtensionRegexes();
        assertThat(regexList)
                .isNotEmpty()
                .allSatisfy(regex -> assertThat(regex.getTests())
                        .as("%s", regex.getDescription())
                        .isNotEmpty()
                        .allSatisfy(s -> assertThat(s)
                                .isNotEmpty()
                                .containsPattern(regex.getRegexCompiled())));
    }
}