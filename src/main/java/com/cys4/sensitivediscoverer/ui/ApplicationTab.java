/*
Copyright (C) 2023 CYS4 Srl
See the file 'LICENSE' for copying permission
*/
package com.cys4.sensitivediscoverer.ui;

import javax.swing.*;

public interface ApplicationTab {
    JPanel getPanel();

    String getTabName();
}
