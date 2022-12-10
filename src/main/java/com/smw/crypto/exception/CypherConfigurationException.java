package com.smw.crypto.exception;

//TODO javadoc: wrapper per le eccezioni lanciate dai costruttori dei cifrari
public class CypherConfigurationException extends CryptoException {

	private static final long serialVersionUID = -1943117290515843976L;

	public CypherConfigurationException(String message) {
		super(message);
	}

	public CypherConfigurationException(Throwable throwable) {
		super(throwable);
	}
}
