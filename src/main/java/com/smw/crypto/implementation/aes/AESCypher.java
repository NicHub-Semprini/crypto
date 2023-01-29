package com.smw.crypto.implementation.aes;

import java.nio.charset.Charset;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import com.smw.crypto.core.Constants;
import com.smw.crypto.core.SymmetricCypher;
import com.smw.crypto.exception.CypherConfigurationException;
import com.smw.crypto.implementation.aes.AESConstants.AlgorithmImplementations;
import com.smw.crypto.implementation.aes.AESConstants.IvLengths;
import com.smw.crypto.implementation.aes.AESConstants.KeyLengths;

/**
 * Concrete class implementing an AES cipher
 */
public class AESCypher extends SymmetricCypher {

	/**
	 * Creates an {@link AESCypher}
	 * @param algorithmImplementation the implementation of the encryption/decryption algorithm
	 * @param encoding the charset to use during encryption/decryption of strings
	 * @param key the encryption/decryption key
	 * @param iv the initialization vector (iv)
	 * @param keyLength the length of the encryption/decryption key
	 * @param ivLength the length of the iv
	 * @throws CypherConfigurationException wrapping exceptions thrown by the underlying {@link Cipher}s
	 */
	public AESCypher(AlgorithmImplementations algorithmImplementation, Charset encoding, SecretKey key, IvParameterSpec iv, KeyLengths keyLength, IvLengths ivLength)
		throws CypherConfigurationException {
		super(AESConstants.ALGORITHM_FAMILY, algorithmImplementation.value(), encoding, key, iv, keyLength.value(), ivLength.value());
	}
	
	/**
	 * Creates an {@link AESCypher} using CBC algorithm and UTF-8 encoding
	 * @param key the encryption/decryption key
	 * @param iv the initialization vector (iv)
	 * @param keyLength the length of the encryption/decryption key
	 * @param ivLength the length of the iv
	 * @throws CypherConfigurationException wrapping exceptions thrown by the underlying {@link Cipher}s
	 */
	public AESCypher(SecretKey key, IvParameterSpec iv, KeyLengths keyLength, IvLengths ivLength)
		throws CypherConfigurationException {
		this(AlgorithmImplementations.CBC, Constants.DEFAULT_CHARSET, key, iv, keyLength, ivLength);
	}
}
