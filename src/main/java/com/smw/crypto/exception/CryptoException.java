package com.smw.crypto.exception;

// TODO javadoc: superclasse per tutte le eccezioni lanciate dalla libreria
public class CryptoException extends Exception {

	private static final long serialVersionUID = -6616590118200736789L;

	public CryptoException(String message) {
		super(message);
	}

	public CryptoException(Throwable throwable) {
		super(throwable);
	}
}
