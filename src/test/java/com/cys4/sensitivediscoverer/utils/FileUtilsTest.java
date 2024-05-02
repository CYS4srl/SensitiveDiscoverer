package com.cys4.sensitivediscoverer.utils;

import com.cys4.sensitivediscoverer.model.HttpSection;
import com.cys4.sensitivediscoverer.model.RegexEntity;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class FileUtilsTest {

    @Test
    void testExportRegexListToCSV() {
        List<RegexEntity> regexes = List.of(
                // no refinerRegex
                new RegexEntity("Test regex 1", "-----BEGIN", true, EnumSet.of(HttpSection.REQ_BODY, HttpSection.RES_HEADERS, HttpSection.RES_BODY), ""),
                // all
                new RegexEntity("Test regex 2", "-----BEGIN", true, HttpSection.RES, ".+$"),
                // empty section; no refinerRegex
                new RegexEntity("Test regex 3", "-----BEGIN", true, EnumSet.noneOf(HttpSection.class), null),
                // all
                new RegexEntity("Test regex 4", "(?i)example\\.app", true, HttpSection.ALL, "[a-z\\-]{1,64}$")
        );
        assertThat(FileUtils.exportRegexListToCSV(regexes)).containsExactly(
                "\"description\",\"regex\",\"refinerRegex\",\"sections\"",
                "\"Test regex 1\",\"-----BEGIN\",\"\",\"req_body|res_headers|res_body\"",
                "\"Test regex 2\",\"-----BEGIN\",\".+$\",\"res_headers|res_body\"",
                "\"Test regex 3\",\"-----BEGIN\",\"\",\"\"",
                "\"Test regex 4\",\"(?i)example\\.app\",\"[a-z\\-]{1,64}$\",\"req_url|req_headers|req_body|res_headers|res_body\""
        );
    }

    @Test
    void testExportRegexListToJSON() {
        List<RegexEntity> regexes = List.of(
                // no refinerRegex
                new RegexEntity("Test regex 1", "-----BEGIN", true, EnumSet.of(HttpSection.REQ_BODY, HttpSection.RES_HEADERS, HttpSection.RES_BODY), ""),
                // all
                new RegexEntity("Test regex 2", "-----BEGIN", false, HttpSection.RES, ".+$"),
                // empty section; no refinerRegex
                new RegexEntity("Test regex 3", "-----BEGIN", true, EnumSet.noneOf(HttpSection.class), null),
                // all
                new RegexEntity("Test regex 4", "(?i)example\\.app", true, HttpSection.ALL, "[a-z\\-]{1,64}$")
        );
        assertThat(FileUtils.exportRegexListToJson(regexes, true)).isEqualTo(
                "[{\"active\":true,\"description\":\"Test regex 1\",\"regex\":\"-----BEGIN\",\"sections\":[\"req_body\",\"res_headers\",\"res_body\"]},{\"active\":false,\"description\":\"Test regex 2\",\"regex\":\"-----BEGIN\",\"refinerRegex\":\".+$\",\"sections\":[\"res_headers\",\"res_body\"]},{\"active\":true,\"description\":\"Test regex 3\",\"regex\":\"-----BEGIN\",\"sections\":[]},{\"active\":true,\"description\":\"Test regex 4\",\"regex\":\"(?i)example\\\\.app\",\"refinerRegex\":\"[a-z\\\\-]{1,64}$\",\"sections\":[\"req_url\",\"req_headers\",\"req_body\",\"res_headers\",\"res_body\"]}]"
        );
    }

    @Test
    void testImportRegexListFromCSV_extendedFormat() {
        List<RegexEntity> regexesList = new ArrayList<>();
        List<String> csv = List.of("""
                "description","regex","refinerRegex","sections"
                "Test regex 1","-----BEGIN","","req_body|res_body|res_headers"
                "Test regex 2","-----BEGIN",".+",""
                "Test regex 3","(?i)key:(\\"".+?\\"")","",""
                "Test regex 4","(?i)example\\.app","[a-z\\-]{1,64}","all"
                "Test regex 5","(?i)example\\.app","[a-z\\-]{1,64}$","res"
                """.split("\n")
        );
        FileUtils.importRegexListFromCSV(csv, regexesList);
        assertThat(regexesList).containsExactly(
                // no refinerRegex
                new RegexEntity("Test regex 1", "-----BEGIN", true, EnumSet.of(HttpSection.REQ_BODY, HttpSection.RES_HEADERS, HttpSection.RES_BODY), ""),
                // no sections
                new RegexEntity("Test regex 2", "-----BEGIN", true, EnumSet.noneOf(HttpSection.class), ".+"),
                // no section/refinerRegex; escape of double quotes
                new RegexEntity("Test regex 3", "(?i)key:(\\\".+?\\\")", true, EnumSet.noneOf(HttpSection.class), null),
                // dollar sign of refinerRegex
                new RegexEntity("Test regex 4", "(?i)example\\.app", true, HttpSection.ALL, "[a-z\\-]{1,64}$"),
                // dollar sign of refinerRegex
                new RegexEntity("Test regex 5", "(?i)example\\.app", true, HttpSection.RES, "[a-z\\-]{1,64}")
        );
    }

    @Test
    void testImportRegexListFromCSV_simpleFormat() {
        List<RegexEntity> regexesList = new ArrayList<>();
        List<String> csv = List.of("""
                "description","regex"
                "Test regex 1","-----BEGIN"
                "Test regex 2","(?i)key:(\\"".+?\\"")"
                """.split("\n")
        );
        FileUtils.importRegexListFromCSV(csv, regexesList);
        assertThat(regexesList).containsExactly(
                // simple regex
                new RegexEntity("Test regex 1", "-----BEGIN", true, HttpSection.RES, ""),
                // escape of double quotes
                new RegexEntity("Test regex 2", "(?i)key:(\\\".+?\\\")", true, HttpSection.RES, null)
        );
    }

    @Test
    void testImportRegexListFromJSON() {
        List<RegexEntity> regexesList = new ArrayList<>();
        String json = """
                [
                {"description":"Test regex 1","regex":"-----BEGIN","sections":["req_body","res"]},
                {"description":"Test regex 2","regex":"-----BEGIN","refinerRegex":".+"},
                {"active":false,"description":"Test regex 3","regex":"-----BEGIN","sections":[],"refinerRegex":""},
                {"active":true,"description":"Test regex 4","regex":"(?i)example\\\\.app","refinerRegex":"[a-z\\\\-]{1,64}$","sections":["all"]}
                ]
                """;
        FileUtils.importRegexListFromJSON(json, regexesList, true);
        assertThat(regexesList).containsExactly(
                // no refinerRegex
                new RegexEntity("Test regex 1", "-----BEGIN", true, EnumSet.of(HttpSection.REQ_BODY, HttpSection.RES_HEADERS, HttpSection.RES_BODY), ""),
                // default sections
                new RegexEntity("Test regex 2", "-----BEGIN", true, HttpSection.RES, ".+$"),
                // no section/refinerRegex
                new RegexEntity("Test regex 3", "-----BEGIN", false, EnumSet.noneOf(HttpSection.class), null),
                // all
                new RegexEntity("Test regex 4", "(?i)example\\.app", true, HttpSection.ALL, "[a-z\\-]{1,64}$")
        );
    }

    @Test
    void testUnescapeCsvQuotes() {
        assertThat(FileUtils.unescapeCsvQuotes("test\"test\"\"test")).isEqualTo("test\"test\"test");
        assertThat(FileUtils.unescapeCsvQuotes(null)).isEqualTo("");
        assertThat(FileUtils.unescapeCsvQuotes("")).isEqualTo("");
    }
}