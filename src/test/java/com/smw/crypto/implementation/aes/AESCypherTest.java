package com.smw.crypto.implementation.aes;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.smw.crypto.BaseCryptoTest;
import com.smw.crypto.core.Constants;
import com.smw.crypto.exception.CypherOperationException;
import com.smw.crypto.implementation.aes.AESConstants.AlgorithmImplementations;
import com.smw.crypto.implementation.aes.AESConstants.IvLengths;
import com.smw.crypto.implementation.aes.AESConstants.KeyLengths;

class AESCypherTest extends BaseCryptoTest {
	
	private final SecureRandom random = new SecureRandom();
	private final Charset encoding = StandardCharsets.UTF_8;
	
	String password;
	String salt;
	int iteractions;
	byte[] seed = new byte[8];
	String inputString;
	byte[] inputBytes;
	KeyLengths keyLength;
	
	@BeforeEach
	void printVariables() {
		password = String.valueOf(random.nextInt());
		salt = String.valueOf(random.nextInt());
		iteractions = random.nextInt(69) + 1;
		random.nextBytes(seed);
		inputString = String.valueOf(random.nextLong());
		inputBytes = inputString.getBytes(encoding);
		keyLength = KeyLengths.values()[random.nextInt(KeyLengths.values().length)];
		log.info("encoding = {}", encoding);
		log.info("password = {}", password);
		log.info("salt = {}", salt);
		log.info("iteractions = {}", iteractions);
		log.info("inputString = {}", inputString);
		log.info("inputBytes = {}", inputBytes);
		log.info("keyLength = {}", keyLength);
	}
	
	@Test
	void defaultValues() throws Exception {
		IvParameterSpec iv = AESUtils.generateIv();
		SecretKey randomKey = AESUtils.generateRandomKey(keyLength);
		AESCypher cypher = new AESCypher(randomKey, iv, keyLength, IvLengths.IV_16);
		Assertions.assertEquals(AESConstants.ALGORITHM_FAMILY, cypher.getAlgorithmFamily());
		Assertions.assertEquals(AlgorithmImplementations.CBC.value(), cypher.getAlgorithmImplementation());
		Assertions.assertEquals(Constants.DEFAULT_CHARSET, cypher.getEncoding());
		{
			final String encryptedString = cypher.encryptToString(inputString);
			final String decryptedString = cypher.decryptToString(encryptedString);
			Assertions.assertEquals(inputString, decryptedString);
		}
		{
			final byte[] encryptedBytes = cypher.encrypt(inputString);
			final String decryptedString = cypher.decryptToString(encryptedBytes);
			Assertions.assertEquals(inputString, decryptedString);
		}
		{
			final String encryptedString = cypher.encryptToString(inputBytes);
			final byte[] decryptedBytes = cypher.decrypt(encryptedString);
			Assertions.assertArrayEquals(inputBytes, decryptedBytes);
		}
		{
			final byte[] encryptedBytes = cypher.encrypt(inputBytes);
			final byte[] decryptedBytes = cypher.decrypt(encryptedBytes);
			Assertions.assertArrayEquals(inputBytes, decryptedBytes);
		}
	}
	
	@Test
	void exceptions() throws Exception {
		IvParameterSpec iv = AESUtils.generateIv();
		SecretKey randomKey = AESUtils.generateRandomKey(keyLength);
		AESCypher cypher = new AESCypher(randomKey, iv, keyLength, IvLengths.IV_16);
		Cipher cypherE = Cipher.getInstance("AES/CBC/NoPadding"); 
		cypherE.init(Cipher.ENCRYPT_MODE, randomKey, iv);
		setValue(cypher, "cipherE", cypherE, 1);
		Cipher cypherD = Cipher.getInstance("AES/CBC/NoPadding"); 
		cypherD.init(Cipher.DECRYPT_MODE, randomKey, iv);
		setValue(cypher, "cipherD", cypherD, 1);
		Assertions.assertThrows(CypherOperationException.class, () -> cypher.encrypt(inputBytes));
		Assertions.assertThrows(CypherOperationException.class, () -> cypher.decrypt(inputBytes));
	}
	
	@Test
	void cbc() throws Exception {
		IvParameterSpec iv = AESUtils.generateIv();
		SecretKey randomKey = AESUtils.generateRandomKey(keyLength);
		AESCypher cypher = new AESCypher(AlgorithmImplementations.CBC, encoding, randomKey, iv, keyLength, IvLengths.IV_16);
		{
			final String encryptedString = cypher.encryptToString(inputString);
			final String decryptedString = cypher.decryptToString(encryptedString);
			Assertions.assertEquals(inputString, decryptedString);
		}
		{
			final byte[] encryptedBytes = cypher.encrypt(inputString);
			final String decryptedString = cypher.decryptToString(encryptedBytes);
			Assertions.assertEquals(inputString, decryptedString);
		}
		{
			final String encryptedString = cypher.encryptToString(inputBytes);
			final byte[] decryptedBytes = cypher.decrypt(encryptedString);
			Assertions.assertArrayEquals(inputBytes, decryptedBytes);
		}
		{
			final byte[] encryptedBytes = cypher.encrypt(inputBytes);
			final byte[] decryptedBytes = cypher.decrypt(encryptedBytes);
			Assertions.assertArrayEquals(inputBytes, decryptedBytes);
		}
	}
	
	@Test
	void cfb() throws Exception {
		IvParameterSpec iv = AESUtils.generateIv();
		SecretKey randomKey = AESUtils.generateRandomKey(keyLength);
		AESCypher cypher = new AESCypher(AlgorithmImplementations.CFB, encoding, randomKey, iv, keyLength, IvLengths.IV_16);
		{
			final String encryptedString = cypher.encryptToString(inputString);
			final String decryptedString = cypher.decryptToString(encryptedString);
			Assertions.assertEquals(inputString, decryptedString);
		}
		{
			final byte[] encryptedBytes = cypher.encrypt(inputString);
			final String decryptedString = cypher.decryptToString(encryptedBytes);
			Assertions.assertEquals(inputString, decryptedString);
		}
		{
			final String encryptedString = cypher.encryptToString(inputBytes);
			final byte[] decryptedBytes = cypher.decrypt(encryptedString);
			Assertions.assertArrayEquals(inputBytes, decryptedBytes);
		}
		{
			final byte[] encryptedBytes = cypher.encrypt(inputBytes);
			final byte[] decryptedBytes = cypher.decrypt(encryptedBytes);
			Assertions.assertArrayEquals(inputBytes, decryptedBytes);
		}
	}
	
	@Test
	void cfb32() throws Exception {
		IvParameterSpec iv = AESUtils.generateIv();
		SecretKey randomKey = AESUtils.generateRandomKey(keyLength);
		AESCypher cypher = new AESCypher(AlgorithmImplementations.CFB32, encoding, randomKey, iv, keyLength, IvLengths.IV_16);
		{
			final String encryptedString = cypher.encryptToString(inputString);
			final String decryptedString = cypher.decryptToString(encryptedString);
			Assertions.assertEquals(inputString, decryptedString);
		}
		{
			final byte[] encryptedBytes = cypher.encrypt(inputString);
			final String decryptedString = cypher.decryptToString(encryptedBytes);
			Assertions.assertEquals(inputString, decryptedString);
		}
		{
			final String encryptedString = cypher.encryptToString(inputBytes);
			final byte[] decryptedBytes = cypher.decrypt(encryptedString);
			Assertions.assertArrayEquals(inputBytes, decryptedBytes);
		}
		{
			final byte[] encryptedBytes = cypher.encrypt(inputBytes);
			final byte[] decryptedBytes = cypher.decrypt(encryptedBytes);
			Assertions.assertArrayEquals(inputBytes, decryptedBytes);
		}
	}
	
	@Test
	void ecb() throws Exception {
		IvParameterSpec iv = null;
		SecretKey randomKey = AESUtils.generateRandomKey(keyLength);
		AESCypher cypher = new AESCypher(AlgorithmImplementations.ECB, encoding, randomKey, iv, keyLength, IvLengths.IV_0);
		{
			final String encryptedString = cypher.encryptToString(inputString);
			final String decryptedString = cypher.decryptToString(encryptedString);
			Assertions.assertEquals(inputString, decryptedString);
		}
		{
			final byte[] encryptedBytes = cypher.encrypt(inputString);
			final String decryptedString = cypher.decryptToString(encryptedBytes);
			Assertions.assertEquals(inputString, decryptedString);
		}
		{
			final String encryptedString = cypher.encryptToString(inputBytes);
			final byte[] decryptedBytes = cypher.decrypt(encryptedString);
			Assertions.assertArrayEquals(inputBytes, decryptedBytes);
		}
		{
			final byte[] encryptedBytes = cypher.encrypt(inputBytes);
			final byte[] decryptedBytes = cypher.decrypt(encryptedBytes);
			Assertions.assertArrayEquals(inputBytes, decryptedBytes);
		}
	}
	
	@Test
	void ofb() throws Exception {
		IvParameterSpec iv = AESUtils.generateIv();
		SecretKey randomKey = AESUtils.generateRandomKey(keyLength);
		AESCypher cypher = new AESCypher(AlgorithmImplementations.OFB, encoding, randomKey, iv, keyLength, IvLengths.IV_16);
		{
			final String encryptedString = cypher.encryptToString(inputString);
			final String decryptedString = cypher.decryptToString(encryptedString);
			Assertions.assertEquals(inputString, decryptedString);
		}
		{
			final byte[] encryptedBytes = cypher.encrypt(inputString);
			final String decryptedString = cypher.decryptToString(encryptedBytes);
			Assertions.assertEquals(inputString, decryptedString);
		}
		{
			final String encryptedString = cypher.encryptToString(inputBytes);
			final byte[] decryptedBytes = cypher.decrypt(encryptedString);
			Assertions.assertArrayEquals(inputBytes, decryptedBytes);
		}
		{
			final byte[] encryptedBytes = cypher.encrypt(inputBytes);
			final byte[] decryptedBytes = cypher.decrypt(encryptedBytes);
			Assertions.assertArrayEquals(inputBytes, decryptedBytes);
		}
	}
	
	@Test
	void ofb32() throws Exception {
		IvParameterSpec iv = AESUtils.generateIv();
		SecretKey randomKey = AESUtils.generateRandomKey(keyLength);
		AESCypher cypher = new AESCypher(AlgorithmImplementations.OFB32, encoding, randomKey, iv, keyLength, IvLengths.IV_16);
		{
			final String encryptedString = cypher.encryptToString(inputString);
			final String decryptedString = cypher.decryptToString(encryptedString);
			Assertions.assertEquals(inputString, decryptedString);
		}
		{
			final byte[] encryptedBytes = cypher.encrypt(inputString);
			final String decryptedString = cypher.decryptToString(encryptedBytes);
			Assertions.assertEquals(inputString, decryptedString);
		}
		{
			final String encryptedString = cypher.encryptToString(inputBytes);
			final byte[] decryptedBytes = cypher.decrypt(encryptedString);
			Assertions.assertArrayEquals(inputBytes, decryptedBytes);
		}
		{
			final byte[] encryptedBytes = cypher.encrypt(inputBytes);
			final byte[] decryptedBytes = cypher.decrypt(encryptedBytes);
			Assertions.assertArrayEquals(inputBytes, decryptedBytes);
		}
	}
	
	@Test
	void pcbc() throws Exception {
		IvParameterSpec iv = AESUtils.generateIv();
		SecretKey randomKey = AESUtils.generateRandomKey(keyLength);
		AESCypher cypher = new AESCypher(AlgorithmImplementations.PCBC, encoding, randomKey, iv, keyLength, IvLengths.IV_16);
		{
			final String encryptedString = cypher.encryptToString(inputString);
			final String decryptedString = cypher.decryptToString(encryptedString);
			Assertions.assertEquals(inputString, decryptedString);
		}
		{
			final byte[] encryptedBytes = cypher.encrypt(inputString);
			final String decryptedString = cypher.decryptToString(encryptedBytes);
			Assertions.assertEquals(inputString, decryptedString);
		}
		{
			final String encryptedString = cypher.encryptToString(inputBytes);
			final byte[] decryptedBytes = cypher.decrypt(encryptedString);
			Assertions.assertArrayEquals(inputBytes, decryptedBytes);
		}
		{
			final byte[] encryptedBytes = cypher.encrypt(inputBytes);
			final byte[] decryptedBytes = cypher.decrypt(encryptedBytes);
			Assertions.assertArrayEquals(inputBytes, decryptedBytes);
		}
	}
}
