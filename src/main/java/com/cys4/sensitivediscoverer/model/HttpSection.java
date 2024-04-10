package com.cys4.sensitivediscoverer.model;

import java.util.EnumSet;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.cys4.sensitivediscoverer.utils.Messages.getLocaleString;

/**
 * Enum to identify all the various section that a regex can match in an HttpProxyItem object.
 */
public enum HttpSection {
    REQ_URL,
    REQ_HEADERS,
    REQ_BODY,
    RES_HEADERS,
    RES_BODY;

    public static final EnumSet<HttpSection> REQ = EnumSet.of(HttpSection.REQ_URL, HttpSection.REQ_HEADERS, HttpSection.REQ_BODY);
    public static final EnumSet<HttpSection> RES = EnumSet.of(HttpSection.RES_HEADERS, HttpSection.RES_BODY);
    public static final EnumSet<HttpSection> ALL = EnumSet.allOf(HttpSection.class);

    public static EnumSet<HttpSection> getDefault() {
        return HttpSection.RES;
    }

    /**
     * Converts a list of serialized sections to an EnumSet of sections
     *
     * @param sections List of the serialized sections
     * @return An EnumSet with all the sections in the given list
     */
    public static EnumSet<HttpSection> deserializeSections(List<String> sections) {
        if (Objects.isNull(sections))
            return HttpSection.getDefault();

        return sections
                .stream()
                .flatMap(section -> switch (section) {
                    case "req_url" -> Stream.of(HttpSection.REQ_URL);
                    case "req_headers" -> Stream.of(HttpSection.REQ_HEADERS);
                    case "req_body" -> Stream.of(HttpSection.REQ_BODY);
                    case "res_headers" -> Stream.of(HttpSection.RES_HEADERS);
                    case "res_body" -> Stream.of(HttpSection.RES_BODY);
                    case "req" -> HttpSection.REQ.stream();
                    case "res" -> HttpSection.RES.stream();
                    case "all" -> HttpSection.ALL.stream();
                    default -> null;
                })
                .filter(Objects::nonNull)
                .collect(Collectors.toCollection(() -> EnumSet.noneOf(HttpSection.class)));
    }

    /**
     * Convert an EnumSet of sections into a list of serialized sections
     *
     * @param sections EnumSet of sections
     * @return A list of the sections in the EnumSet as serialized strings
     */
    public static List<String> serializeSections(EnumSet<HttpSection> sections) {
        return sections
                .stream()
                .flatMap(section -> switch (section) {
                    case REQ_URL -> Stream.of("req_url");
                    case REQ_HEADERS -> Stream.of("req_headers");
                    case REQ_BODY -> Stream.of("req_body");
                    case RES_HEADERS -> Stream.of("res_headers");
                    case RES_BODY -> Stream.of("res_body");
                })
                .filter(Objects::nonNull)
                .collect(Collectors.<String>toList());
    }

    @Override
    public String toString() {
        return switch (this) {
            case REQ_URL -> getLocaleString("regex-section-reqURL");
            case REQ_HEADERS -> getLocaleString("regex-section-reqHeaders");
            case REQ_BODY -> getLocaleString("regex-section-reqBody");
            case RES_HEADERS -> getLocaleString("regex-section-resHeaders");
            case RES_BODY -> getLocaleString("regex-section-resBody");
        };
    }
}
