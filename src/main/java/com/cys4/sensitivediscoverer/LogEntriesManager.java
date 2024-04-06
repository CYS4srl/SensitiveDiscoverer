package com.cys4.sensitivediscoverer;

import com.cys4.sensitivediscoverer.model.LogEntity;

import java.util.ArrayList;
import java.util.List;

public class LogEntriesManager {
    private final List<LogEntity> logEntries;
    private final List<LogEntriesListener> listeners;

    public LogEntriesManager() {
        this.logEntries = new ArrayList<>();
        this.listeners = new ArrayList<>();
    }

    public void add(LogEntity entry) {
        logEntries.add(entry);
        listeners.forEach(listener -> listener.onSizeChange(logEntries.size()));
    }

    public void remove(LogEntity entry) {
        logEntries.remove(entry);
        listeners.forEach(listener -> listener.onSizeChange(logEntries.size()));
    }

    public void clear() {
        logEntries.clear();
        listeners.forEach(listener -> listener.onSizeChange(logEntries.size()));
    }

    public int size() {
        return logEntries.size();
    }

    public LogEntity get(int index) {
        return logEntries.get(index);
    }

    /**
     * Returns an unmodifiable List containing all the log entries.
     * @return a <code>List</code> containing the log entries.
     */
    public List<LogEntity> getAll() {
        return List.copyOf(logEntries);
    }

    public boolean contains(LogEntity entry) {
        return logEntries.contains(entry);
    }

    public int indexOf(LogEntity entry) {
        return logEntries.indexOf(entry);
    }

    public void subscribeChangeListener(LogEntriesListener listener) {
        listeners.add(listener);
    }

    public void unsubscribeChangeListener(LogEntriesListener listener) {
        listeners.remove(listener);
    }
}
