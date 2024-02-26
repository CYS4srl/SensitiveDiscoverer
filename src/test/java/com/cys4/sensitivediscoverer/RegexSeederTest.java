package com.cys4.sensitivediscoverer;

import com.cys4.sensitivediscoverer.model.RegexEntity;
import org.assertj.core.api.Condition;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class RegexSeederTest {
    private final Condition<String> positiveMatch = new Condition<>(s -> !(s.startsWith("!")), "positive match");

    /**
     * Assert that each regex in the list has at least one test string and also assert that each test string matches correctly
     * @param regexList The regex list
     */
    private void testRegexList(List<RegexEntity> regexList) {
        assertThat(regexList)
                .isNotEmpty()
                .allSatisfy(regex -> {
                    assertThat(regex.getTests())
                            .as("%s", regex.getDescription())
                            .isNotEmpty()
                            .haveAtLeastOne(positiveMatch)
                            .allSatisfy(s -> {
                                if (s.startsWith("!"))
                                    assertThat(s.substring(1))
                                            .isNotEmpty()
                                            .doesNotContainPattern(regex.getRegexCompiled());
                                else
                                    assertThat(s)
                                            .isNotEmpty()
                                            .containsPattern(regex.getRegexCompiled());
                            });
                });
    }

    @Test
    public void generalRegexesMatching() {
        testRegexList(RegexSeeder.getGeneralRegexes());
    }

    @Test
    public void extensionRegexesMatching() {
        testRegexList(RegexSeeder.getExtensionRegexes());
    }
}