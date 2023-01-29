package com.smw.crypto.core;

import java.nio.charset.Charset;

import javax.crypto.Cipher;

import com.smw.crypto.exception.CypherOperationException;

/**
 * Abstract superclass for both symmetric and asymmetric ciphers
 */
public abstract class Cypher {

	protected final String algorithmFamily;
	protected final String algorithmImplementation;
	protected final Charset encoding;
	
	/**
	 * Creates a {@link Cypher}
	 * @param algorithmFamily the family of the encryption/decryption algorithm
	 * @param algorithmImplementation the implementation of the encryption/decryption algorithm
	 * @param encoding the charset to use during encryption/decryption of strings
	 */
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

	/**
	 * Encrypts given input string producing a base64-encoded output string
	 * @param input the string to encrypt
	 * @return the base64-encoded encrypted string
	 * @throws CypherOperationException wrapping exceptions thrown by the underlying {@link Cipher}
	 */
	public abstract String encryptToString(String input)
		throws CypherOperationException;

	/**
	 * Encrypts given input bytes producing a base64-encoded output string
	 * @param input the bytes to encrypt
	 * @return the base64-encoded encrypted string
	 * @throws CypherOperationException wrapping exceptions thrown by the underlying {@link Cipher}
	 */
	public abstract String encryptToString(byte[] input)
		throws CypherOperationException;
	
	/**
	 * Encrypts given input string producing bytes
	 * @param input the string to encrypt
	 * @return the encrypted bytes
	 * @throws CypherOperationException wrapping exceptions thrown by the underlying {@link Cipher}
	 */
	public abstract byte[] encrypt(String input)
		throws CypherOperationException;
	
	/**
	 * Encrypts given input bytes producing output bytes
	 * @param input the bytes to encrypt
	 * @return the encrypted bytes
	 * @throws CypherOperationException wrapping exceptions thrown by the underlying {@link Cipher}
	 */
	public abstract byte[] encrypt(byte[] input)
		throws CypherOperationException;

	/**
	 * Decrypts given base64-encoded input string producing an output string
	 * @param input the base64-encoded string to decrypt
	 * @return the decrypted string
	 * @throws CypherOperationException wrapping exceptions thrown by the underlying {@link Cipher}
	 */
	public abstract String decryptToString(String input)
		throws CypherOperationException;
	
	/**
	 * Decrypts given bytes producing a string
	 * @param input the bytes to decrypt
	 * @return the decrypted string
	 * @throws CypherOperationException wrapping exceptions thrown by the underlying {@link Cipher}
	 */
	public abstract String decryptToString(byte[] input)
		throws CypherOperationException;
	
	/**
	 * Decrypts given base64-encoded input string producing bytes
	 * @param input the base64-encoded string to decrypt
	 * @return the decrypted bytes
	 * @throws CypherOperationException wrapping exceptions thrown by the underlying {@link Cipher}
	 */
	public abstract byte[] decrypt(String input)
		throws CypherOperationException;
	
	/**
	 * Decrypts given input bytes producing output bytes
	 * @param input the bytes to decrypt
	 * @return the decrypted bytes
	 * @throws CypherOperationException wrapping exceptions thrown by the underlying {@link Cipher}
	 */
	public abstract byte[] decrypt(byte[] input)
		throws CypherOperationException;
}
