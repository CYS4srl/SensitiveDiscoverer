package com.cys4.sensitivediscoverer.utils;

import com.cys4.sensitivediscoverer.model.HttpSection;
import com.cys4.sensitivediscoverer.model.JsonRegexEntity;
import com.cys4.sensitivediscoverer.model.RegexEntity;
import com.cys4.sensitivediscoverer.model.RegexListContext;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.reflect.TypeToken;

import java.io.IOException;
import java.io.PrintWriter;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.cys4.sensitivediscoverer.Messages.getLocaleString;

public class FileUtils {

    public static void writeLinesToFile(String fileName, List<String> lines) {
        try {
            PrintWriter pwt = new PrintWriter(fileName, StandardCharsets.UTF_8);
            lines.forEach(pwt::println);
            pwt.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static List<String> readLinesFromFile(String fileName) {
        try {
            return Files.readAllLines(Path.of(fileName));
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static void exportRegexListToCSV(String csvFile, List<RegexEntity> regexEntities) {
        List<String> lines = new ArrayList<>();

        lines.add("\"description\",\"regex\",\"refinerRegex\",\"sections\"");
        regexEntities.forEach(regexEntity -> {
            String description = regexEntity.getDescription().replaceAll("\"", "\"\"");
            String regex = regexEntity.getRegex().replaceAll("\"", "\"\"");
            String refinerRegex = regexEntity.getRefinerRegex().orElse("");
            String sections = String
                    .join("|", HttpSection.serializeSections(regexEntity.getSections()))
                    .replaceAll("\"", "\"\"");
            lines.add(String.format("\"%s\",\"%s\",\"%s\",\"%s\"", description, regex, refinerRegex, sections));
        });

        writeLinesToFile(csvFile, lines);
    }

    public static void exportRegexListToJSON(String jsonFile, List<RegexEntity> regexEntities) {
        List<JsonObject> lines;
        lines = regexEntities
                .stream()
                .map(regexEntity -> {
                    JsonObject json = new JsonObject();
                    json.addProperty("description", regexEntity.getDescription());
                    json.addProperty("regex", regexEntity.getRegex());
                    regexEntity.getRefinerRegex().ifPresent(s -> json.addProperty("refinerRegex", s));
                    JsonArray sections = new JsonArray();
                    HttpSection.serializeSections(regexEntity.getSections()).forEach(sections::add);
                    json.add("sections", sections);
                    return json;
                })
                .collect(Collectors.toList());

        Gson gson = new GsonBuilder().disableHtmlEscaping().create();
        Type tListEntries = (new TypeToken<ArrayList<JsonObject>>() {
        }).getType();

        writeLinesToFile(jsonFile, List.of(gson.toJson(lines, tListEntries)));
    }

    public static void importRegexListFromFileCSV(String csvFilepath, RegexListContext ctx) {
        List<String> lines = readLinesFromFile(csvFilepath);
        if (Objects.isNull(lines)) return;

        String alreadyAddedMsg = importRegexListFromCSV(lines, ctx);

        SwingUtils.showMessageDialog(
                getLocaleString("options-list-open-alreadyPresentTitle"),
                getLocaleString("options-list-open-alreadyPresentWarn"),
                alreadyAddedMsg);
    }

    public static String importRegexListFromCSV(List<String> csvLines, RegexListContext ctx) {
        StringBuilder alreadyAddedMsg = new StringBuilder();

        // skip header line if present
        int startRow = csvLines.get(0).startsWith("\"description\",\"regex\"") ? 1 : 0;
        csvLines.subList(startRow, csvLines.size())
                .stream()
                .map(RegexEntity::checkRegexEntityFromCSV)
                .flatMap(Optional::stream)
                .map(match -> new RegexEntity(
                        unescapeCsvQuotes(match.group(1)),
                        unescapeCsvQuotes(match.group(2)),
                        true,
                        HttpSection.deserializeSections(decodeSectionListFromCSV(match.group(4))),
                        unescapeCsvQuotes(match.group(3))))
                .forEachOrdered(newRegex -> {
                    if (!ctx.regexEntities().contains(newRegex)) {
                        ctx.regexEntities().add(newRegex);
                    } else {
                        alreadyAddedMsg.append(String.format("%s - %s\n", newRegex.getDescription(), newRegex.getRegex()));
                    }
                });
        return alreadyAddedMsg.toString();
    }

    public static void importRegexListFromFileJSON(String jsonFilepath, RegexListContext ctx) {
        List<String> lines = readLinesFromFile(jsonFilepath);
        if (Objects.isNull(lines)) return;

        String alreadyAddedMsg = importRegexListFromJSON(String.join("", lines), ctx);

        SwingUtils.showMessageDialog(
                getLocaleString("options-list-open-alreadyPresentTitle"),
                getLocaleString("options-list-open-alreadyPresentWarn"),
                alreadyAddedMsg);
    }

    public static String importRegexListFromJSON(String json, RegexListContext ctx) {
        Gson gson = new Gson();
        StringBuilder alreadyAddedMsg = new StringBuilder();
        Type tArrayListRegexEntity = new TypeToken<ArrayList<JsonRegexEntity>>() {
        }.getType();

        Stream.of(json)
                .<List<JsonRegexEntity>>map(regexList -> gson.fromJson(regexList, tArrayListRegexEntity))
                .filter(Objects::nonNull)
                .flatMap(Collection::stream)
                .map(element -> new RegexEntity(
                        element.getDescription(),
                        element.getRegex(),
                        true,
                        HttpSection.deserializeSections(element.getSections()),
                        element.getRefinerRegex()))
                .forEachOrdered(newRegex -> {
                    if (!ctx.regexEntities().contains(newRegex)) {
                        ctx.regexEntities().add(newRegex);
                    } else {
                        alreadyAddedMsg.append(String.format("%s - %s\n", newRegex.getDescription(), newRegex.getRegex()));
                    }
                });
        return alreadyAddedMsg.toString();
    }

    /**
     * @param encodedSections
     * @return
     */
    private static List<String> decodeSectionListFromCSV(String encodedSections) {
        return Objects.isNull(encodedSections) ? null : List.of(unescapeCsvQuotes(encodedSections).split("\\|"));
    }


    /**
     * @param input The text to unescape
     * @return the input with "" converted to ", or an empty string if input is null
     */
    public static String unescapeCsvQuotes(String input) {
        return Objects.nonNull(input) ? input.replaceAll("\"\"", "\"") : "";
    }
}
