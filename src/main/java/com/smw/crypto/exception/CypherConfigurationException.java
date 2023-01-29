package com.smw.crypto.exception;

/**
 * Wrapper for exceptions typically thrown by constructor methods
 */
public class CypherConfigurationException extends CryptoException {

	private static final long serialVersionUID = -1943117290515843976L;

	public CypherConfigurationException(String message) {
		super(message);
	}

	public CypherConfigurationException(Throwable throwable) {
		super(throwable);
	}
}
