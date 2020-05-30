package com.daon.idxAuthRequestNode;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LoggerWrapper {
	
	private static final String LOGGER_NAME = "amAuth";
	private static final String LOGGER_PREFIX = "IDX: ";

	private Logger debugLogger;

	private boolean initialized = false;

	private void init() {
		if (initialized) {
			return;
		}
		try {
			debugLogger = LoggerFactory.getLogger(LOGGER_NAME);
		} catch (Exception ex) {
			debugLogger = null;
		}
		initialized = true;
	}
	
	public void debug(String message) {
		init();
		if (debugLogger != null) {
			debugLogger.debug(LOGGER_PREFIX + message);
		}
	}
	
	public void debug(String message, Object... info) {
		init();
		if (debugLogger != null) {
			debugLogger.debug(LOGGER_PREFIX + message, info);
		}
	}

	public void warn(String message) {
		init();
		if (debugLogger != null) {
			debugLogger.warn(LOGGER_PREFIX + message);
		}
	}
	
	public void warn(String message, Object... info) {
		init();
		if (debugLogger != null) {
			debugLogger.warn(LOGGER_PREFIX + message, info);
		}
	}
	
	public void info(String message) {
		init();
		if (debugLogger != null) {
			debugLogger.info(LOGGER_PREFIX + message);
		}
	}
	
	public void info(String message, Object... info) {
		init();
		if (debugLogger != null) {
			debugLogger.info(LOGGER_PREFIX +message, info);
		}
	}

	public void warning(String message, Object... info) {
		init();
		if (debugLogger != null) {
			debugLogger.warn(LOGGER_PREFIX + message, info);
		}
	}
	
	public void error(String message) {
		init();
		if (debugLogger != null) {
			debugLogger.error(LOGGER_PREFIX +message);
		}
	}

	public void error(String message, Object... info) {
		init();
		if (debugLogger != null) {
			debugLogger.error(LOGGER_PREFIX + message, info);
		}
	}
}
