package com.smw.crypto.core;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.smw.crypto.BaseCryptoTest;
import com.smw.crypto.exception.CypherConfigurationException;
import com.smw.crypto.exception.CypherOperationException;

class SymmetricCypherTest extends BaseCryptoTest {
	
	private final SecureRandom random = new SecureRandom();
	private final String algorithmFamily = "AES";
	private final String algorithmImplementation = "AES/OFB32/PKCS5Padding";
	private final Charset encoding = StandardCharsets.UTF_8;
	private final byte[] keySeed = new byte[16];
	private final byte[] ivSeed = new byte[16];
	private final SecretKey key = new SecretKeySpec(keySeed, algorithmFamily);
	private final IvParameterSpec iv = new IvParameterSpec(ivSeed);
	
	private int keyLength;
	private int ivLength; 
	
	@BeforeEach
	void printVariables() {
		keyLength = random.nextInt();
		ivLength = random.nextInt();
		log.info("algorithmFamily = {}", algorithmFamily);
		log.info("algorithmImplementation = {}", algorithmImplementation);
		log.info("encoding = {}", encoding);
		log.info("keySeed = {}", keySeed);
		log.info("ivSeed = {}", ivSeed);
		log.info("keyLength = {}", keyLength);
		log.info("ivLength = {}", ivLength);
	}
		
	@Test
	void constructorException() {
		final String overridedAlgorithmFamily = "overridedAlgorithmFamily";
		final String overridedAlgorithmImplementation = "overridedAlgorithmImplementation";
		log.info("overridedAlgorithmFamily = {}", overridedAlgorithmFamily);
		log.info("overridedAlgorithmImplementation = {}", overridedAlgorithmImplementation);
		Assertions.assertThrows(CypherConfigurationException.class, () -> createCypher(overridedAlgorithmFamily, overridedAlgorithmImplementation, encoding, key, iv, keyLength, ivLength));
	}
	
	@Test
	void getters() throws Exception {
		SymmetricCypher cypher = createCypher(algorithmFamily, algorithmImplementation, encoding, key, iv, keyLength, ivLength);
		Assertions.assertEquals(algorithmFamily, cypher.getAlgorithmFamily());
		Assertions.assertEquals(algorithmImplementation, cypher.getAlgorithmImplementation());
		Assertions.assertEquals(encoding, cypher.getEncoding());
		Assertions.assertEquals(keyLength, cypher.getKeyLength());
		Assertions.assertEquals(ivLength, cypher.getIvLength());
	}

	private SymmetricCypher createCypher(String algorithmFamily, String algorithmImplementation, Charset encoding, SecretKey key, IvParameterSpec iv, int keyLength, int ivLength) throws Exception {
		return new SymmetricCypher(algorithmFamily, algorithmImplementation, encoding, key, iv, keyLength, ivLength) {
			
			@Override
			public String encryptToString(byte[] input) throws CypherOperationException {
				return null;
			}
			
			@Override
			public String encryptToString(String input) throws CypherOperationException {
				return null;
			}
			
			@Override
			public byte[] encrypt(byte[] input) throws CypherOperationException {
				return null;
			}
			
			@Override
			public byte[] encrypt(String input) throws CypherOperationException {
				return null;
			}
			
			@Override
			public String decryptToString(byte[] input) throws CypherOperationException {
				return null;
			}
			
			@Override
			public String decryptToString(String input) throws CypherOperationException {
				return null;
			}
			
			@Override
			public byte[] decrypt(byte[] input) throws CypherOperationException {
				return null;
			}
			
			@Override
			public byte[] decrypt(String input) throws CypherOperationException {
				return null;
			}
		};
	}
}
