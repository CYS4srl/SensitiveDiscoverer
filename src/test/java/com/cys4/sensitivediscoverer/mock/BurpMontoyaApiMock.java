package com.cys4.sensitivediscoverer.mock;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.burpsuite.BurpSuite;
import burp.api.montoya.collaborator.Collaborator;
import burp.api.montoya.comparer.Comparer;
import burp.api.montoya.decoder.Decoder;
import burp.api.montoya.extension.Extension;
import burp.api.montoya.http.Http;
import burp.api.montoya.intruder.Intruder;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.organizer.Organizer;
import burp.api.montoya.persistence.Persistence;
import burp.api.montoya.proxy.Proxy;
import burp.api.montoya.repeater.Repeater;
import burp.api.montoya.scanner.Scanner;
import burp.api.montoya.scope.Scope;
import burp.api.montoya.sitemap.SiteMap;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.utilities.Utilities;
import burp.api.montoya.websocket.WebSockets;
import org.apache.commons.lang3.NotImplementedException;

public class BurpMontoyaApiMock implements MontoyaApi {
    private final Extension extension = new ExtensionMock();
    private final Proxy proxy = new ProxyMock();
    private final UserInterface userInterface = new UserInterfaceMock();

    @Override
    public Extension extension() {
        return this.extension;
    }

    @Override
    public Proxy proxy() {
        return this.proxy;
    }

    @Override
    public UserInterface userInterface() {
        return this.userInterface;
    }

    @Override
    public BurpSuite burpSuite() {
        throw new NotImplementedException();
    }

    @Override
    public Collaborator collaborator() {
        throw new NotImplementedException();
    }

    @Override
    public Comparer comparer() {
        throw new NotImplementedException();
    }

    @Override
    public Decoder decoder() {
        throw new NotImplementedException();
    }

    @Override
    public Http http() {
        throw new NotImplementedException();
    }

    @Override
    public Intruder intruder() {
        throw new NotImplementedException();
    }

    @Override
    public Logging logging() {
        throw new NotImplementedException();
    }

    @Override
    public Organizer organizer() {
        throw new NotImplementedException();
    }

    @Override
    public Persistence persistence() {
        throw new NotImplementedException();
    }

    @Override
    public Repeater repeater() {
        throw new NotImplementedException();
    }

    @Override
    public Scanner scanner() {
        throw new NotImplementedException();
    }

    @Override
    public Scope scope() {
        throw new NotImplementedException();
    }

    @Override
    public SiteMap siteMap() {
        throw new NotImplementedException();
    }

    @Override
    public Utilities utilities() {
        throw new NotImplementedException();
    }

    @Override
    public WebSockets websockets() {
        throw new NotImplementedException();
    }
}
