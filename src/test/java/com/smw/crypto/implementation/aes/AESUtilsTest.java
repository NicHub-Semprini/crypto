package com.smw.crypto.implementation.aes;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.smw.crypto.BaseCryptoTest;
import com.smw.crypto.implementation.aes.AESConstants.AlgorithmImplementations;
import com.smw.crypto.implementation.aes.AESConstants.KeyLengths;

class AESUtilsTest extends BaseCryptoTest {
	
	private final SecureRandom random = new SecureRandom();
	private final Charset encoding = StandardCharsets.UTF_8;
	
	String password;
	String salt;
	int iteractions;
	byte[] seed = new byte[8];
	String inputString;
	byte[] inputBytes;
	private KeyLengths keyLength;
	private AlgorithmImplementations algorithm;
	
	@BeforeEach
	void printVariables() {
		password = String.valueOf(random.nextInt());
		salt = String.valueOf(random.nextInt());
		iteractions = random.nextInt(69) + 1;
		random.nextBytes(seed);
		inputString = String.valueOf(random.nextLong());
		inputBytes = inputString.getBytes(encoding);
		keyLength = KeyLengths.values()[random.nextInt(KeyLengths.values().length)];
		algorithm = AlgorithmImplementations.values()[random.nextInt(AlgorithmImplementations.values().length)];
		log.info("encoding = {}", encoding);
		log.info("password = {}", password);
		log.info("salt = {}", salt);
		log.info("iteractions = {}", iteractions);
		log.info("inputString = {}", inputString);
		log.info("inputBytes = {}", inputBytes);
		log.info("keyLength = {}", keyLength);
		log.info("algorithm = {}", algorithm);
	}
	
	@Test
	void generateIvWithoutSeed() throws Exception {
		IvParameterSpec iv1 = AESUtils.generateIv();
		IvParameterSpec iv2 = AESUtils.generateIv();
		Assertions.assertNotEquals(new String(iv1.getIV()), new String(iv2.getIV()));
	}
	
	@Test
	void generateIvWithSeed() throws Exception {
		IvParameterSpec iv1 = AESUtils.generateIv(seed);
		IvParameterSpec iv2 = AESUtils.generateIv(seed);
		Assertions.assertEquals(new String(iv1.getIV()), new String(iv2.getIV()));
	}
	
	@Test
	void fromByteToByteWithRandomKey() throws Exception {
		IvParameterSpec iv = generateIv(algorithm);
		SecretKey randomKey = AESUtils.generateRandomKey(keyLength);
		byte[] encryptedBytes = AESUtils.encrypt(algorithm, randomKey, iv, inputBytes);
		String encryptedString = AESUtils.encryptToString(algorithm, randomKey, iv, inputBytes);
		byte[] decryptedBytes1 = AESUtils.decrypt(algorithm, randomKey, iv, encryptedBytes);
		byte[] decryptedBytes2 = AESUtils.decrypt(algorithm, randomKey, iv, encryptedString);
		Assertions.assertArrayEquals(inputBytes, decryptedBytes1);
		Assertions.assertArrayEquals(inputBytes, decryptedBytes2);
	}
	
	@Test
	void fromByteToStringWithRandomKey() throws Exception {
		IvParameterSpec iv = generateIv(algorithm);
		SecretKey randomKey = AESUtils.generateRandomKey(keyLength);
		byte[] encryptedBytes = AESUtils.encrypt(algorithm, randomKey, iv, inputBytes);
		String encryptedString = AESUtils.encryptToString(algorithm, randomKey, iv, inputBytes);
		String decryptedString1 = AESUtils.decryptToString(algorithm, randomKey, iv, encryptedBytes);
		String decryptedString2 = AESUtils.decryptToString(algorithm, randomKey, iv, encryptedString, encoding);
		Assertions.assertEquals(inputString, decryptedString1);
		Assertions.assertEquals(inputString, decryptedString2);
		Assertions.assertArrayEquals(inputBytes, decryptedString1.getBytes(encoding));
		Assertions.assertArrayEquals(inputBytes, decryptedString2.getBytes(encoding));
	}
	
	@Test
	void fromStringToByteWithRandomKey() throws Exception {
		IvParameterSpec iv = generateIv(algorithm);
		SecretKey randomKey = AESUtils.generateRandomKey(keyLength);
		byte[] encryptedBytes = AESUtils.encrypt(algorithm, randomKey, iv, inputString);
		String encryptedString = AESUtils.encryptToString(algorithm, randomKey, iv, inputString);
		byte[] decryptedBytes1 = AESUtils.decrypt(algorithm, randomKey, iv, encryptedBytes);
		byte[] decryptedBytes2 = AESUtils.decrypt(algorithm, randomKey, iv, encryptedString);
		Assertions.assertEquals(inputString, new String(decryptedBytes1, encoding));
		Assertions.assertEquals(inputString, new String(decryptedBytes2, encoding));
		Assertions.assertArrayEquals(inputString.getBytes(encoding), decryptedBytes1);
		Assertions.assertArrayEquals(inputString.getBytes(encoding), decryptedBytes2);
	}
	
	@Test
	void fromStringToStringWithRandomKey() throws Exception {
		IvParameterSpec iv = generateIv(algorithm);
		SecretKey randomKey = AESUtils.generateRandomKey(keyLength);
		byte[] encryptedBytes = AESUtils.encrypt(algorithm, randomKey, iv, inputString);
		String encryptedString = AESUtils.encryptToString(algorithm, randomKey, iv, inputString);
		String decryptedString1 = AESUtils.decryptToString(algorithm, randomKey, iv, encryptedBytes);
		String decryptedString2 = AESUtils.decryptToString(algorithm, randomKey, iv, encryptedString);
		Assertions.assertEquals(inputString, decryptedString1);
		Assertions.assertEquals(inputString, decryptedString2);
	}
	
	@Test
	void fromByteToByteWithPasswordKey() throws Exception {
		IvParameterSpec iv = generateIv(algorithm);
		SecretKey passwordKey = AESUtils.generateKeyFromPassword(password, salt, iteractions, keyLength);
		byte[] encryptedBytes = AESUtils.encrypt(algorithm, passwordKey, iv, inputBytes);
		String encryptedString = AESUtils.encryptToString(algorithm, passwordKey, iv, inputBytes);
		byte[] decryptedBytes1 = AESUtils.decrypt(algorithm, passwordKey, iv, encryptedBytes);
		byte[] decryptedBytes2 = AESUtils.decrypt(algorithm, passwordKey, iv, encryptedString);
		Assertions.assertArrayEquals(inputBytes, decryptedBytes1);
		Assertions.assertArrayEquals(inputBytes, decryptedBytes2);
	}
	
	@Test
	void fromByteToStringWithPasswordKey() throws Exception {
		IvParameterSpec iv = generateIv(algorithm);
		SecretKey passwordKey = AESUtils.generateKeyFromPassword(password, salt, iteractions, keyLength);
		byte[] encryptedBytes = AESUtils.encrypt(algorithm, passwordKey, iv, inputBytes);
		String encryptedString = AESUtils.encryptToString(algorithm, passwordKey, iv, inputBytes);
		String decryptedString1 = AESUtils.decryptToString(algorithm, passwordKey, iv, encryptedBytes);
		String decryptedString2 = AESUtils.decryptToString(algorithm, passwordKey, iv, encryptedString);
		Assertions.assertEquals(inputString, decryptedString1);
		Assertions.assertEquals(inputString, decryptedString2);
		Assertions.assertArrayEquals(inputBytes, decryptedString1.getBytes(encoding));
		Assertions.assertArrayEquals(inputBytes, decryptedString2.getBytes(encoding));
	}
	
	@Test
	void fromStringToByteWithPasswordKey() throws Exception {
		IvParameterSpec iv = generateIv(algorithm);
		SecretKey passwordKey = AESUtils.generateKeyFromPassword(password, salt, iteractions, keyLength);
		byte[] encryptedBytes = AESUtils.encrypt(algorithm, passwordKey, iv, inputString);
		String encryptedString = AESUtils.encryptToString(algorithm, passwordKey, iv, inputString);
		byte[] decryptedBytes1 = AESUtils.decrypt(algorithm, passwordKey, iv, encryptedBytes);
		byte[] decryptedBytes2 = AESUtils.decrypt(algorithm, passwordKey, iv, encryptedString);
		Assertions.assertEquals(inputString, new String(decryptedBytes1, encoding));
		Assertions.assertEquals(inputString, new String(decryptedBytes2, encoding));
		Assertions.assertArrayEquals(inputString.getBytes(encoding), decryptedBytes1);
		Assertions.assertArrayEquals(inputString.getBytes(encoding), decryptedBytes2);
	}
	
	@Test
	void fromStringToStringWithPasswordKey() throws Exception {
		IvParameterSpec iv = generateIv(algorithm);
		SecretKey passwordKey = AESUtils.generateKeyFromPassword(password, salt, iteractions, keyLength);
		byte[] encryptedBytes = AESUtils.encrypt(algorithm, passwordKey, iv, inputString);
		String encryptedString = AESUtils.encryptToString(algorithm, passwordKey, iv, inputString);
		String decryptedString1 = AESUtils.decryptToString(algorithm, passwordKey, iv, encryptedBytes);
		String decryptedString2 = AESUtils.decryptToString(algorithm, passwordKey, iv, encryptedString);
		Assertions.assertEquals(inputString, decryptedString1);
		Assertions.assertEquals(inputString, decryptedString2);
	}
	
	private IvParameterSpec generateIv(AlgorithmImplementations algorithm) throws Exception {
		IvParameterSpec result = null;
		if(algorithm != AlgorithmImplementations.ECB) {
			result = AESUtils.generateIv();
		}
		return result;
	}
}
