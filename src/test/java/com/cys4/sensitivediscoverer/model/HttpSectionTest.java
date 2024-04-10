package com.cys4.sensitivediscoverer.model;

import org.junit.jupiter.api.Test;

import java.util.EnumSet;
import java.util.List;

import static com.cys4.sensitivediscoverer.utils.Messages.getLocaleString;
import static org.assertj.core.api.Assertions.assertThat;

class HttpSectionTest {

    @Test
    void getDefault() {
        assertThat(HttpSection.getDefault()).isEqualTo(HttpSection.RES);
    }

    @Test
    void deserializeSections() {
        assertThat(HttpSection.deserializeSections(List.of("all"))).containsExactlyInAnyOrder(HttpSection.REQ_URL, HttpSection.REQ_HEADERS, HttpSection.REQ_BODY, HttpSection.RES_HEADERS, HttpSection.RES_BODY);
        assertThat(HttpSection.deserializeSections(List.of("req"))).containsExactlyInAnyOrder(HttpSection.REQ_URL, HttpSection.REQ_HEADERS, HttpSection.REQ_BODY);
        assertThat(HttpSection.deserializeSections(List.of("res"))).containsExactlyInAnyOrder(HttpSection.RES_HEADERS, HttpSection.RES_BODY);
        assertThat(HttpSection.deserializeSections(List.of("req_url"))).containsExactly(HttpSection.REQ_URL);
        assertThat(HttpSection.deserializeSections(List.of("req_headers"))).containsExactly(HttpSection.REQ_HEADERS);
        assertThat(HttpSection.deserializeSections(List.of("req_body"))).containsExactly(HttpSection.REQ_BODY);
        assertThat(HttpSection.deserializeSections(List.of("res_headers"))).containsExactly(HttpSection.RES_HEADERS);
        assertThat(HttpSection.deserializeSections(List.of("res_body"))).containsExactly(HttpSection.RES_BODY);
        assertThat(HttpSection.deserializeSections(List.of())).isEmpty();
    }

    @Test
    void serializeSections() {
        assertThat(HttpSection.serializeSections(HttpSection.ALL)).containsExactlyInAnyOrder("req_url", "req_headers", "req_body", "res_headers", "res_body");
        assertThat(HttpSection.serializeSections(HttpSection.REQ)).containsExactlyInAnyOrder("req_url", "req_headers", "req_body");
        assertThat(HttpSection.serializeSections(HttpSection.RES)).containsExactlyInAnyOrder("res_headers", "res_body");
        assertThat(HttpSection.serializeSections(EnumSet.of(HttpSection.REQ_URL))).containsExactly("req_url");
        assertThat(HttpSection.serializeSections(EnumSet.of(HttpSection.REQ_HEADERS))).containsExactly("req_headers");
        assertThat(HttpSection.serializeSections(EnumSet.of(HttpSection.REQ_BODY))).containsExactly("req_body");
        assertThat(HttpSection.serializeSections(EnumSet.of(HttpSection.RES_HEADERS))).containsExactly("res_headers");
        assertThat(HttpSection.serializeSections(EnumSet.of(HttpSection.RES_BODY))).containsExactly("res_body");
        assertThat(HttpSection.serializeSections(EnumSet.noneOf(HttpSection.class))).isEmpty();
    }

    @Test
    void testToString() {
        assertThat(HttpSection.REQ_URL.toString()).isEqualTo(getLocaleString("regex-section-reqURL"));
        assertThat(HttpSection.REQ_HEADERS.toString()).isEqualTo(getLocaleString("regex-section-reqHeaders"));
        assertThat(HttpSection.REQ_BODY.toString()).isEqualTo(getLocaleString("regex-section-reqBody"));
        assertThat(HttpSection.RES_HEADERS.toString()).isEqualTo(getLocaleString("regex-section-resHeaders"));
        assertThat(HttpSection.RES_BODY.toString()).isEqualTo(getLocaleString("regex-section-resBody"));
    }
}