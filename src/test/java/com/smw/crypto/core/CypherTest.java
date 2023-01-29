package com.smw.crypto.core;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.smw.crypto.BaseCryptoTest;
import com.smw.crypto.exception.CypherOperationException;

class CypherTest extends BaseCryptoTest {
	
	private final String algorithmFamily = "algorithmFamily";
	private final String algorithmImplementation = "algorithmImplementation";
	private final Charset encoding = StandardCharsets.UTF_8;
	
	@BeforeEach
	void printVariables() {
		log.info("algorithmFamily = {}", algorithmFamily);
		log.info("algorithmImplementation = {}", algorithmImplementation);
		log.info("encoding = {}", encoding);
	}
	
	@Test
	void getters() throws Exception {
		Cypher cypher = createCypher(algorithmFamily, algorithmImplementation, encoding);
		Assertions.assertEquals(algorithmFamily, cypher.getAlgorithmFamily());
		Assertions.assertEquals(algorithmImplementation, cypher.getAlgorithmImplementation());
		Assertions.assertEquals(encoding, cypher.getEncoding());
	}

	private Cypher createCypher(String algorithmFamily, String algorithmImplementation, Charset encoding) {
		return new Cypher(algorithmFamily, algorithmImplementation, encoding) {
			
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
