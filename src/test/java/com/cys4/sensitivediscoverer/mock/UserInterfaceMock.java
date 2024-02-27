package com.cys4.sensitivediscoverer.mock;

import burp.api.montoya.core.Registration;
import burp.api.montoya.ui.Theme;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.editor.*;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;
import burp.api.montoya.ui.editor.extension.HttpResponseEditorProvider;
import burp.api.montoya.ui.editor.extension.WebSocketMessageEditorProvider;
import burp.api.montoya.ui.menu.MenuBar;
import burp.api.montoya.ui.swing.SwingUtils;
import org.apache.commons.lang3.NotImplementedException;

import java.awt.*;

public class UserInterfaceMock implements UserInterface {
    @Override
    public void applyThemeToComponent(Component component) {
    }
    @Override
    public Registration registerSuiteTab(String s, Component component) {
        return null;
    }
    @Override
    public HttpRequestEditor createHttpRequestEditor(EditorOptions... editorOptions) {
        return new HttpRequestEditorMock();
    }

    @Override
    public HttpResponseEditor createHttpResponseEditor(EditorOptions... editorOptions) {
        return new HttpResponseEditorMock();
    }

    @Override
    public MenuBar menuBar() {
        throw new NotImplementedException();
    }

    @Override
    public Registration registerContextMenuItemsProvider(ContextMenuItemsProvider contextMenuItemsProvider) {
        throw new NotImplementedException();
    }

    @Override
    public Registration registerHttpRequestEditorProvider(HttpRequestEditorProvider httpRequestEditorProvider) {
        throw new NotImplementedException();
    }

    @Override
    public Registration registerHttpResponseEditorProvider(HttpResponseEditorProvider httpResponseEditorProvider) {
        throw new NotImplementedException();
    }

    @Override
    public Registration registerWebSocketMessageEditorProvider(WebSocketMessageEditorProvider webSocketMessageEditorProvider) {
        throw new NotImplementedException();
    }

    @Override
    public RawEditor createRawEditor(EditorOptions... editorOptions) {
        throw new NotImplementedException();
    }

    @Override
    public WebSocketMessageEditor createWebSocketMessageEditor(EditorOptions... editorOptions) {
        throw new NotImplementedException();
    }

    @Override
    public Theme currentTheme() {
        throw new NotImplementedException();
    }

    @Override
    public Font currentEditorFont() {
        throw new NotImplementedException();
    }

    @Override
    public Font currentDisplayFont() {
        throw new NotImplementedException();
    }

    @Override
    public SwingUtils swingUtils() {
        throw new NotImplementedException();
    }
}
