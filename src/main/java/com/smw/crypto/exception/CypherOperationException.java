package com.smw.crypto.exception;

//TODO javadoc: wrapper per le eccezioni lanciate durante le crypt/decrypt
public class CypherOperationException extends CryptoException {

	private static final long serialVersionUID = -8139830105096429230L;

	public CypherOperationException(String message) {
		super(message);
	}

	public CypherOperationException(Throwable throwable) {
		super(throwable);
	}
}
