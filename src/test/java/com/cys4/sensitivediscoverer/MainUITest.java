package com.cys4.sensitivediscoverer;

import burp.api.montoya.MontoyaApi;
import com.cys4.sensitivediscoverer.mock.BurpMontoyaApiMock;
import com.cys4.sensitivediscoverer.model.ScannerOptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.swing.*;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

class MainUITest {
    private MainUI mainUI;
    private MontoyaApi burpApi;

    @BeforeEach
    void setUp() throws Exception {
        this.burpApi = new BurpMontoyaApiMock();
        this.mainUI = new MainUI(burpApi);
        assertThat(this.mainUI.isInterfaceInitialized()).isFalse();
    }

    @Test
    void testGetScannerOptions() {
        assertThat(this.mainUI.getScannerOptions())
                .isNotNull()
                .isInstanceOf(ScannerOptions.class);
    }

    @Test
    void testGetMainPanel() {
        assertThat(this.mainUI.getMainPanel()).isNull();

        this.mainUI.initializeUI();
        await().atMost(30, SECONDS).until(this.mainUI::isInterfaceInitialized);
        assertThat(this.mainUI.isInterfaceInitialized()).isTrue();
        assertThat(this.mainUI.getMainPanel()).isNotNull();

        assertThat(this.mainUI.getMainPanel().getTabCount()).isEqualTo(3);
        assertThat(this.mainUI.getMainPanel().getComponentAt(0)).isInstanceOf(JPanel.class);
        assertThat(this.mainUI.getMainPanel().getTitleAt(0)).isEqualTo("Logger");
        assertThat(this.mainUI.getMainPanel().getComponentAt(1)).isInstanceOf(JPanel.class);
        assertThat(this.mainUI.getMainPanel().getTitleAt(1)).isEqualTo("Options");
        assertThat(this.mainUI.getMainPanel().getComponentAt(2)).isInstanceOf(JPanel.class);
        assertThat(this.mainUI.getMainPanel().getTitleAt(2)).isEqualTo("About");
    }

    @Test
    void testGetCallbacks() {
        assertThat(this.burpApi).isNotNull();
        assertThat(this.mainUI.getBurpApi()).isSameAs(this.burpApi);
    }

    @Test
    void testGetGeneralRegexList() {
        assertThat(this.mainUI.getGeneralRegexList()).isNotNull();
    }

    @Test
    void testGetExtensionsRegexList() {
        assertThat(this.mainUI.getExtensionsRegexList()).isNotNull();
    }

    @Test
    void testGetExtensionName() {
        assertThat(mainUI.getExtensionName()).isEqualTo("Sensitive Discoverer");
    }
}