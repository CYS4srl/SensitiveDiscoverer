package com.cys4.sensitivediscoverer.mock;

import burp.ITextEditor;
import org.apache.commons.lang3.NotImplementedException;

import javax.swing.*;
import java.awt.*;

public class TextEditorMock implements ITextEditor {
    @Override
    public Component getComponent() {
        return new JPanel();
    }

    @Override
    public void setEditable(boolean b) {
        throw new NotImplementedException();
    }

    @Override
    public byte[] getText() {
        throw new NotImplementedException();
    }

    @Override
    public void setText(byte[] bytes) {
        throw new NotImplementedException();
    }

    @Override
    public boolean isTextModified() {
        throw new NotImplementedException();
    }

    @Override
    public byte[] getSelectedText() {
        throw new NotImplementedException();
    }

    @Override
    public int[] getSelectionBounds() {
        throw new NotImplementedException();
    }

    @Override
    public void setSearchExpression(String s) {
        throw new NotImplementedException();
    }
}
