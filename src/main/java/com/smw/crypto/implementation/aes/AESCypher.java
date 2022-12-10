package com.smw.crypto.implementation.aes;

import java.nio.charset.Charset;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import com.smw.crypto.core.SymmetricCypher;
import com.smw.crypto.exception.CypherConfigurationException;

// TODO javadoc
public class AESCypher extends SymmetricCypher {

	// TODO javadoc
	protected AESCypher(String algorithmFamily, String algorithmImplementation, Charset encoding, SecretKey key, IvParameterSpec iv, int keyLength, int ivLength, String secureRandomProvider, String secureRandomAlgorithm)
		throws CypherConfigurationException {
		super(algorithmFamily, algorithmImplementation, encoding, key, iv, keyLength, ivLength, secureRandomProvider, secureRandomAlgorithm);
	}
}
