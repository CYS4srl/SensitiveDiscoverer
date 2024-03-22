package com.cys4.sensitivediscoverer.utils;

import com.cys4.sensitivediscoverer.model.HttpSection;
import com.cys4.sensitivediscoverer.model.RegexEntity;
import com.cys4.sensitivediscoverer.model.RegexListContext;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class FileUtilsTest {

//    @Test
//    void testExportRegexListToCSV() {
//    }
//
//    @Test
//    void testExportRegexListToJSON() {
//    }

    @Test
    void testImportRegexListFromCSV_extendedFormat() {
        RegexListContext ctx = new RegexListContext(new ArrayList<>());
        List<String> csv = List.of("""
                "description","regex","refinerRegex","sections"
                "Test regex 1","-----BEGIN","","req_body|res_body|res_headers"
                "Test regex 2","-----BEGIN",".+",""
                "Test regex 3","(?i)key:(\\"".+?\\"")","",""
                "Test regex 4","(?i)example\\.app","[a-z\\-]{1,64}","all"
                "Test regex 5","(?i)example\\.app","[a-z\\-]{1,64}$","res"
                """.split("\n")
        );
        FileUtils.importRegexListFromCSV(csv, ctx);
        assertThat(ctx.regexEntities()).containsExactly(
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
        RegexListContext ctx = new RegexListContext(new ArrayList<>());
        List<String> csv = List.of("""
                "description","regex"
                "Test regex 1","-----BEGIN"
                "Test regex 2","(?i)key:(\\"".+?\\"")"
                """.split("\n")
        );
        FileUtils.importRegexListFromCSV(csv, ctx);
        assertThat(ctx.regexEntities()).containsExactly(
                // simple regex
                new RegexEntity("Test regex 1", "-----BEGIN", true, HttpSection.RES, ""),
                // escape of double quotes
                new RegexEntity("Test regex 2", "(?i)key:(\\\".+?\\\")", true, HttpSection.RES, null)
        );
    }

    @Test
    void testImportRegexListFromJSON() {
        RegexListContext ctx = new RegexListContext(new ArrayList<>());
        String json = """
                [
                {"description":"Test regex 1","regex":"-----BEGIN","sections":["req_body","res"]},
                {"description":"Test regex 2","regex":"-----BEGIN","refinerRegex":".+"},
                {"description":"Test regex 3","regex":"-----BEGIN","sections":[],"refinerRegex":""},
                {"description":"Test regex 4","regex":"(?i)example\\\\.app","refinerRegex":"[a-z\\\\-]{1,64}$","sections":["all"]}
                ]
                """;
        FileUtils.importRegexListFromJSON(json, ctx);
        assertThat(ctx.regexEntities()).containsExactly(
                // no refinerRegex
                new RegexEntity("Test regex 1", "-----BEGIN", true, EnumSet.of(HttpSection.REQ_BODY, HttpSection.RES_HEADERS, HttpSection.RES_BODY), ""),
                // default sections
                new RegexEntity("Test regex 2", "-----BEGIN", true, HttpSection.RES, ".+$"),
                // no section/refinerRegex
                new RegexEntity("Test regex 3", "-----BEGIN", true, EnumSet.noneOf(HttpSection.class), null),
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