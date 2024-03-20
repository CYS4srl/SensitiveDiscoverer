package com.cys4.sensitivediscoverer.utils;

import com.cys4.sensitivediscoverer.model.JsonRegexEntity;
import com.cys4.sensitivediscoverer.model.ProxyItemSection;
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
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.regex.Matcher;
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

        lines.add("\"description\",\"regex\",\"sections\"");
        regexEntities.forEach(regexEntity -> {
            String description = regexEntity.getDescription().replaceAll("\"", "\"\"");
            String regex = regexEntity.getRegex().replaceAll("\"", "\"\"");
            String sections = String
                    .join("|", ProxyItemSection.serializeSections(regexEntity.getSections()))
                    .replaceAll("\"", "\"\"");
            lines.add(String.format("\"%s\",\"%s\",\"%s\"", description, regex, sections));
        });

        writeLinesToFile(csvFile, lines);
    }

    public static void exportRegexListToJSON(String jsonFile, List<RegexEntity> regexEntities) {
        List<JsonObject> lines = new ArrayList<>();

        regexEntities.forEach(regexEntity -> {
            JsonObject obj = new JsonObject();
            obj.addProperty("description", regexEntity.getDescription());
            obj.addProperty("regex", regexEntity.getRegex());
            JsonArray sections = new JsonArray();
            ProxyItemSection.serializeSections(regexEntity.getSections()).forEach(sections::add);
            obj.add("sections", sections);
            lines.add(obj);
        });

        GsonBuilder builder = new GsonBuilder().disableHtmlEscaping();
        Gson gson = builder.create();
        Type tListEntries = (new TypeToken<ArrayList<JsonObject>>() {
        }).getType();

        writeLinesToFile(jsonFile, List.of(gson.toJson(lines, tListEntries)));
    }

    public static void importRegexListFromCSV(String csvFile, RegexListContext ctx) {
        StringBuilder alreadyAddedMsg = new StringBuilder();

        List<String> lines = readLinesFromFile(csvFile);
        if (Objects.isNull(lines)) return;

        //Skip header line if present
        int startRow = (lines.get(0).contains("\"description\",\"regex\"")) ? 1 : 0;

        lines.subList(startRow, lines.size()).forEach(line -> {
            Matcher matcher = RegexEntity.checkRegexEntityFromCSV(line);

            if (!matcher.find())
                return;

            //load sections if presents, otherwise set all sections
            boolean hasSections = !(matcher.group(3) == null || matcher.group(3).isBlank());

            String description = matcher.group(1).replaceAll("\"\"", "\"");
            String regex = matcher.group(2).replaceAll("\"\"", "\"");
            List<String> sections = hasSections ? List.of(matcher.group(3).replaceAll("\"\"", "\"").split("\\|")) : null;

            RegexEntity newRegexEntity = new RegexEntity(
                    description,
                    regex,
                    true,
                    hasSections ? ProxyItemSection.deserializeSections(sections) : ProxyItemSection.ALL
            );

            if (!ctx.getRegexEntities().contains(newRegexEntity)) {
                ctx.getRegexEntities().add(newRegexEntity);
            } else {
                alreadyAddedMsg.append(String.format("%s - %s\n", newRegexEntity.getDescription(), newRegexEntity.getRegex()));
            }
        });

        SwingUtils.showMessageDialog(
                getLocaleString("options-list-open-alreadyPresentTitle"),
                getLocaleString("options-list-open-alreadyPresentWarn"),
                alreadyAddedMsg.toString());
    }

    public static void importRegexListFromJSON(String jsonFile, RegexListContext ctx) {
        Gson gson = new Gson();
        StringBuilder alreadyAddedMsg = new StringBuilder();

        List<String> lines = readLinesFromFile(jsonFile);
        if (Objects.isNull(lines)) return;

        Type tArrayListRegexEntity = new TypeToken<ArrayList<JsonRegexEntity>>() {
        }.getType();
        Stream.of(String.join("", lines))
                .<List<JsonRegexEntity>>map(regexList -> gson.fromJson(regexList, tArrayListRegexEntity))
                .filter(Objects::nonNull)
                .flatMap(Collection::stream)
                .map(element -> new RegexEntity(
                        element.getDescription(),
                        element.getRegex(),
                        true,
                        ProxyItemSection.deserializeSections(element.getSections())))
                .forEachOrdered(regexEntity -> {
                    if (!ctx.getRegexEntities().contains(regexEntity)) {
                        ctx.getRegexEntities().add(regexEntity);
                    } else {
                        alreadyAddedMsg
                                .append(regexEntity.getDescription())
                                .append(" - ")
                                .append(regexEntity.getRegex())
                                .append("\n");
                    }
                });

        SwingUtils.showMessageDialog(
                getLocaleString("options-list-open-alreadyPresentTitle"),
                getLocaleString("options-list-open-alreadyPresentWarn"),
                alreadyAddedMsg.toString());
    }
}
