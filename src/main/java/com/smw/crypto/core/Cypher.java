package com.smw.crypto.core;

import java.nio.charset.Charset;

import com.smw.crypto.exception.CypherOperationException;

//TODO javadoc
public abstract class Cypher {

	protected final String algorithmFamily;
	protected final String algorithmImplementation;
	protected final Charset encoding;
	
	// TODO javadoc
	protected Cypher(String algorithmFamily, String algorithmImplementation, Charset encoding) {
		this.algorithmFamily = algorithmFamily;
		this.algorithmImplementation = algorithmImplementation;
		this.encoding = encoding;
	}
	
	/**
	 * @return the algorithmFamily
	 */
	public String getAlgorithmFamily() {
		return algorithmFamily;
	}

	/**
	 * @return the algorithmImplementation
	 */
	public String getAlgorithmImplementation() {
		return algorithmImplementation;
	}

	/**
	 * @return the encoding
	 */
	public Charset getEncoding() {
		return encoding;
	}

	// TODO javadoc
	public abstract String encryptToString(String input)
		throws CypherOperationException;

	// TODO javadoc
	public abstract String encryptToString(byte[] input)
		throws CypherOperationException;
	
	// TODO javadoc
	public abstract byte[] encrypt(String input)
		throws CypherOperationException;
	
	// TODO javadoc
	public abstract byte[] encrypt(byte[] input)
		throws CypherOperationException;

	// TODO javadoc
	public abstract String decryptToString(String input)
		throws CypherOperationException;
	
	// TODO javadoc
	public abstract String decryptToString(byte[] input)
		throws CypherOperationException;
	
	// TODO javadoc
	public abstract byte[] decrypt(String input)
		throws CypherOperationException;
	
	// TODO javadoc
	public abstract byte[] decrypt(byte[] input)
		throws CypherOperationException;
}
