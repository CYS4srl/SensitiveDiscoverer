package com.cys4.sensitivediscoverer.mock;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import org.apache.commons.lang3.NotImplementedException;

import javax.swing.*;
import java.awt.*;
import java.util.Optional;

public class HttpRequestEditorMock implements HttpRequestEditor {
    JPanel uiComponent = new JPanel();

    @Override
    public Component uiComponent() {
        return uiComponent;
    }

    @Override
    public void setSearchExpression(String s) {
    }

    @Override
    public HttpRequest getRequest() {
        throw new NotImplementedException();
    }

    @Override
    public void setRequest(HttpRequest httpRequest) {
    }


    @Override
    public boolean isModified() {
        throw new NotImplementedException();
    }

    @Override
    public int caretPosition() {
        throw new NotImplementedException();
    }

    @Override
    public Optional<Selection> selection() {
        throw new NotImplementedException();
    }

}
