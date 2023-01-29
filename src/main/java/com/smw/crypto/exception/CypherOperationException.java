package com.smw.crypto.exception;

/**
 * Wrapper for exceptions typically thrown by encrypting/decrypting methods
 */
public class CypherOperationException extends CryptoException {

	private static final long serialVersionUID = -8139830105096429230L;

	public CypherOperationException(String message) {
		super(message);
	}

	public CypherOperationException(Throwable throwable) {
		super(throwable);
	}
}
