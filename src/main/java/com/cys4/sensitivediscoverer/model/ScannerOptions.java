/*
Copyright (C) 2023 CYS4 Srl
See the file 'LICENSE' for copying permission
*/
package com.cys4.sensitivediscoverer.model;

public class ScannerOptions {

    /**
     * Checkbox to skip responses not in scope
     */
    private boolean filterInScopeCheckbox;
    /**
     * Checkbox to skip responses over a set max size
     */
    private boolean filterSkipMaxSizeCheckbox;
    /**
     * Checkbox to skip responses of a media MIME-type
     */
    private boolean filterSkipMediaTypeCheckbox;

    /**
     * Max response size in bytes
     */
    private int configMaxResponseSize;
    /**
     * Number of threads to use to scan items
     */
    private int configNumberOfThreads;
    /**
     * The size, in bytes, of the region before the match where the refinerRegex is applied
     */
    private int configRefineContextSize;

    public boolean isFilterInScopeCheckbox() {
        return filterInScopeCheckbox;
    }

    public void setFilterInScopeCheckbox(boolean filterInScopeCheckbox) {
        this.filterInScopeCheckbox = filterInScopeCheckbox;
    }

    public boolean isFilterSkipMaxSizeCheckbox() {
        return filterSkipMaxSizeCheckbox;
    }

    public void setFilterSkipMaxSizeCheckbox(boolean filterSkipMaxSizeCheckbox) {
        this.filterSkipMaxSizeCheckbox = filterSkipMaxSizeCheckbox;
    }

    public boolean isFilterSkipMediaTypeCheckbox() {
        return filterSkipMediaTypeCheckbox;
    }

    public void setFilterSkipMediaTypeCheckbox(boolean filterSkipMediaTypeCheckbox) {
        this.filterSkipMediaTypeCheckbox = filterSkipMediaTypeCheckbox;
    }

    public int getConfigMaxResponseSize() {
        return configMaxResponseSize;
    }

    public void setConfigMaxResponseSize(int configMaxResponseSize) {
        this.configMaxResponseSize = configMaxResponseSize;
    }

    public int getConfigNumberOfThreads() {
        return configNumberOfThreads;
    }

    public void setConfigNumberOfThreads(int configNumberOfThreads) {
        this.configNumberOfThreads = configNumberOfThreads;
    }

    public int getConfigRefineContextSize() {
        return configRefineContextSize;
    }

    public void setConfigRefineContextSize(int configRefineContextSize) {
        this.configRefineContextSize = configRefineContextSize;
    }
}
