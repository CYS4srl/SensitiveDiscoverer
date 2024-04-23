package com.cys4.sensitivediscoverer.utils;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonSyntaxException;
import com.google.gson.reflect.TypeToken;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Objects;
import java.util.Properties;
import java.util.stream.Collectors;


/**
 * Utils package
 */
public class Utils {

    /**
     * Read the content of a resource file.
     *
     * @param filepath Path to the resource file.
     * @return A UTF-8 string with the content of the file read.
     */
    public static String readResourceFile(String filepath) {
        try {
            InputStream inputStream = Utils.getResourceAsStream(filepath);
            if (Objects.isNull(inputStream)) return null;

            InputStreamReader isr = new InputStreamReader(inputStream, StandardCharsets.UTF_8);
            BufferedReader reader = new BufferedReader(isr);

            return reader.lines().collect(Collectors.joining(System.lineSeparator()));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static Properties loadConfigFile() throws Exception {
        Properties properties;

        InputStream input = Utils.getResourceAsStream("config.properties");
        properties = new Properties();
        properties.load(input);
        return properties;
    }

    public static String getExtensionVersion() {
        return Utils.class.getPackage().getImplementationVersion();
    }

    /**
     * Returns an input stream for reading the specified resource.
     *
     * @param name The resource name
     * @return An input stream for reading the resource; null if the resource could not be found or there was an error.
     */
    public static InputStream getResourceAsStream(String name) {
        return Utils.class.getClassLoader().getResourceAsStream(name);
    }

    /**
     * Creates and configures a new {@link Gson} instance for JSON processing.
     *
     * @return A new {@link Gson} instance with HTML escaping disabled.
     */
    public static Gson createGsonBuilder() {
        return new GsonBuilder()
                .disableHtmlEscaping()
                .create();
    }

    /**
     * Parse from JSON a list of objects of the same type
     *
     * @param json      A JSON string representing a list of objects of type T
     * @param itemsType The type of the items in the list
     * @param <T>       The type of the items in the list
     * @return A List containing items of type T, parsed from the JSON string.
     * @throws JsonSyntaxException If the JSON is invalid
     */
    public static <T> List<T> parseListFromJSON(String json, Class<T> itemsType) throws JsonSyntaxException {
        Type typeOfT = TypeToken.getParameterized(List.class, itemsType).getType();
        return new Gson().fromJson(json, typeOfT);
    }
}
