package com.cys4.sensitivediscoverer.ui;

import javax.swing.JPopupMenu;
import javax.swing.JToggleButton;
import javax.swing.event.PopupMenuEvent;
import javax.swing.event.PopupMenuListener;

public class PopupMenuButton extends JToggleButton {
    private final JPopupMenu popup;

    public PopupMenuButton(String name, JPopupMenu menu) {
        super(name);
        this.popup = menu;
        addActionListener(ev -> {
            JToggleButton b = PopupMenuButton.this;
            if (b.isSelected()) {
                popup.show(b, 0, b.getBounds().height);
            } else {
                popup.setVisible(false);
            }
        });
        popup.addPopupMenuListener(new PopupMenuListener() {
            @Override
            public void popupMenuWillBecomeVisible(PopupMenuEvent e) {
            }

            @Override
            public void popupMenuWillBecomeInvisible(PopupMenuEvent e) {
                PopupMenuButton.this.setSelected(false);
            }

            @Override
            public void popupMenuCanceled(PopupMenuEvent e) {
            }
        });
    }
}
