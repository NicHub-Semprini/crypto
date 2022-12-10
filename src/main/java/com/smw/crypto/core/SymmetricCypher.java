package com.smw.crypto.core;

import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import com.smw.crypto.exception.CypherConfigurationException;
import com.smw.crypto.exception.CypherOperationException;

//TODO javadoc
public abstract class SymmetricCypher extends Cypher {

	protected final SecretKey key;
	protected final IvParameterSpec iv;
	protected final int keyLength;
	protected final int ivLength;
	protected final String secureRandomProvider;
	protected final String secureRandomAlgorithm;
	/**
	 * Cipher to be use in encrypting functions
	 */
	protected final Cipher cipherE;
	/**
	 * Cipher to be use in decrypting functions
	 */
	protected final Cipher cipherD;

	// TODO javadoc
	protected SymmetricCypher(String algorithmFamily, String algorithmImplementation, Charset encoding, SecretKey key, IvParameterSpec iv, int keyLength, int ivLength, String secureRandomProvider, String secureRandomAlgorithm)
		throws CypherConfigurationException {
		super(algorithmFamily, algorithmImplementation, encoding);
		this.key = key;
		this.iv = iv;
		this.keyLength = keyLength;
		this.ivLength = ivLength;
		this.secureRandomProvider = secureRandomProvider;
		this.secureRandomAlgorithm = secureRandomAlgorithm;
		try {
			cipherE = Cipher.getInstance(algorithmImplementation);
			cipherE.init(Cipher.ENCRYPT_MODE, key, iv);
			cipherD = Cipher.getInstance(algorithmImplementation);
			cipherD.init(Cipher.DECRYPT_MODE, key, iv);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e) {
			throw new CypherConfigurationException(e);
		}
	}

	/**
	 * @return the keyLength
	 */
	public int getKeyLength() {
		return keyLength;
	}

	/**
	 * @return the ivLength
	 */
	public int getIvLength() {
		return ivLength;
	}

	/**
	 * @return the secureRandomProvider
	 */
	public String getSecureRandomProvider() {
		return secureRandomProvider;
	}

	/**
	 * @return the secureRandomAlgorithm
	 */
	public String getSecureRandomAlgorithm() {
		return secureRandomAlgorithm;
	}
	
	// TODO javadoc
	@Override
	public String encryptToString(String input)
		throws CypherOperationException {
		return new String(Base64.getEncoder().encode(encrypt(input.getBytes(encoding))), encoding);
	}

	// TODO javadoc
	@Override
	public String encryptToString(byte[] input)
		throws CypherOperationException {
		return new String(Base64.getEncoder().encode(encrypt(input)), encoding);
	}

	// TODO javadoc
	@Override
	public byte[] encrypt(String input)
		throws CypherOperationException {
		return encrypt(input.getBytes(encoding));
	}

	// TODO javadoc
	@Override
	public byte[] encrypt(byte[] input)
		throws CypherOperationException {
		try {
			return cipherE.doFinal(input);
		} catch(IllegalBlockSizeException | BadPaddingException e) {
			throw new CypherOperationException(e);
		}
	}

	// TODO javadoc
	@Override
	public String decryptToString(String input)
		throws CypherOperationException {
		return new String(decrypt(Base64.getDecoder().decode(input.getBytes(encoding))), encoding);
	}

	// TODO javadoc
	@Override
	public String decryptToString(byte[] input)
		throws CypherOperationException {
		return new String(decrypt(input), encoding);
	}

	// TODO javadoc
	@Override
	public byte[] decrypt(String input)
		throws CypherOperationException {
		return decrypt(Base64.getDecoder().decode(input.getBytes(encoding)));
	}

	// TODO javadoc
	@Override
	public byte[] decrypt(byte[] input)
		throws CypherOperationException {
		try {
			return cipherD.doFinal(input);
		} catch(IllegalBlockSizeException | BadPaddingException e) {
			throw new CypherOperationException(e);
		}
	}
}
