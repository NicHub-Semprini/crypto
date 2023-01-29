package com.smw.crypto.exception;

/**
 * Superclass of all thrown exceptions
 */
public class CryptoException extends Exception {

	private static final long serialVersionUID = -6616590118200736789L;

	public CryptoException(String message) {
		super(message);
	}

	public CryptoException(Throwable throwable) {
		super(throwable);
	}
}
