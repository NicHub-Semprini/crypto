package com.smw.crypto.aes;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class AESUtilsTest {
	
	private final Logger log = LoggerFactory.getLogger(this.getClass());
	private final SecureRandom random = new SecureRandom();
	private final Charset encoding = StandardCharsets.UTF_8;
	
	String password;
	String salt;
	int iteractions;
	byte[] seed = new byte[8];
	String inputString;
	byte[] inputBytes;
	
	@BeforeEach
	void startUp(TestInfo info) {
		log.info("Executing {}", getTestName(info));
		password = String.valueOf(random.nextInt());
		salt = String.valueOf(random.nextInt());
		iteractions = random.nextInt(69);
		random.nextBytes(seed);
		inputString = String.valueOf(random.nextLong());
		inputBytes = inputString.getBytes(encoding);
	}
	
	@AfterEach
	void tearDown(TestInfo info) {
		log.info("Executed {}", info.getDisplayName().substring(0, info.getDisplayName().length() - 2));
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
		IvParameterSpec iv = AESUtils.generateIv();
		SecretKey randomKey = AESUtils.generateRandomKey(AESUtils.KEY_LENGTH_256);
		byte[] encryptedBytes = AESUtils.encrypt(AESUtils.ALGORITHM_OFB, randomKey, iv, inputBytes);
		String encryptedString = AESUtils.encryptToString(AESUtils.ALGORITHM_OFB, randomKey, iv, inputBytes);
		byte[] decryptedBytes1 = AESUtils.decrypt(AESUtils.ALGORITHM_OFB, randomKey, iv, encryptedBytes);
		byte[] decryptedBytes2 = AESUtils.decrypt(AESUtils.ALGORITHM_OFB, randomKey, iv, encryptedString);
		Assertions.assertArrayEquals(inputBytes, decryptedBytes1);
		Assertions.assertArrayEquals(inputBytes, decryptedBytes2);
	}
	
	@Test
	void fromByteToStringWithRandomKey() throws Exception {
		IvParameterSpec iv = AESUtils.generateIv();
		SecretKey randomKey = AESUtils.generateRandomKey(AESUtils.KEY_LENGTH_256);
		byte[] encryptedBytes = AESUtils.encrypt(AESUtils.ALGORITHM_OFB, randomKey, iv, inputBytes);
		String encryptedString = AESUtils.encryptToString(AESUtils.ALGORITHM_OFB, randomKey, iv, inputBytes);
		String decryptedString1 = AESUtils.decryptToString(AESUtils.ALGORITHM_OFB, randomKey, iv, encryptedBytes);
		String decryptedString2 = AESUtils.decryptToString(AESUtils.ALGORITHM_OFB, randomKey, iv, encryptedString, encoding);
		Assertions.assertEquals(inputString, decryptedString1);
		Assertions.assertEquals(inputString, decryptedString2);
		Assertions.assertArrayEquals(inputBytes, decryptedString1.getBytes(encoding));
		Assertions.assertArrayEquals(inputBytes, decryptedString2.getBytes(encoding));
	}
	
	@Test
	void fromStringToByteWithRandomKey() throws Exception {
		IvParameterSpec iv = AESUtils.generateIv();
		SecretKey randomKey = AESUtils.generateRandomKey(AESUtils.KEY_LENGTH_256);
		byte[] encryptedBytes = AESUtils.encrypt(AESUtils.ALGORITHM_OFB, randomKey, iv, inputString);
		String encryptedString = AESUtils.encryptToString(AESUtils.ALGORITHM_OFB, randomKey, iv, inputString);
		byte[] decryptedBytes1 = AESUtils.decrypt(AESUtils.ALGORITHM_OFB, randomKey, iv, encryptedBytes);
		byte[] decryptedBytes2 = AESUtils.decrypt(AESUtils.ALGORITHM_OFB, randomKey, iv, encryptedString);
		Assertions.assertEquals(inputString, new String(decryptedBytes1, encoding));
		Assertions.assertEquals(inputString, new String(decryptedBytes2, encoding));
		Assertions.assertArrayEquals(inputString.getBytes(encoding), decryptedBytes1);
		Assertions.assertArrayEquals(inputString.getBytes(encoding), decryptedBytes2);
	}
	
	@Test
	void fromStringToStringWithRandomKey() throws Exception {
		IvParameterSpec iv = AESUtils.generateIv();
		SecretKey randomKey = AESUtils.generateRandomKey(AESUtils.KEY_LENGTH_256);
		byte[] encryptedBytes = AESUtils.encrypt(AESUtils.ALGORITHM_OFB, randomKey, iv, inputString);
		String encryptedString = AESUtils.encryptToString(AESUtils.ALGORITHM_OFB, randomKey, iv, inputString);
		String decryptedString1 = AESUtils.decryptToString(AESUtils.ALGORITHM_OFB, randomKey, iv, encryptedBytes);
		String decryptedString2 = AESUtils.decryptToString(AESUtils.ALGORITHM_OFB, randomKey, iv, encryptedString);
		Assertions.assertEquals(inputString, decryptedString1);
		Assertions.assertEquals(inputString, decryptedString2);
	}
	
	@Test
	void fromByteToByteWithPasswordKey() throws Exception {
		IvParameterSpec iv = AESUtils.generateIv();
		SecretKey passwordKey = AESUtils.generateKeyFromPassword(password, salt, iteractions, AESUtils.KEY_LENGTH_256);
		byte[] encryptedBytes = AESUtils.encrypt(AESUtils.ALGORITHM_OFB, passwordKey, iv, inputBytes);
		String encryptedString = AESUtils.encryptToString(AESUtils.ALGORITHM_OFB, passwordKey, iv, inputBytes);
		byte[] decryptedBytes1 = AESUtils.decrypt(AESUtils.ALGORITHM_OFB, passwordKey, iv, encryptedBytes);
		byte[] decryptedBytes2 = AESUtils.decrypt(AESUtils.ALGORITHM_OFB, passwordKey, iv, encryptedString);
		Assertions.assertArrayEquals(inputBytes, decryptedBytes1);
		Assertions.assertArrayEquals(inputBytes, decryptedBytes2);
	}
	
	@Test
	void fromByteToStringWithPasswordKey() throws Exception {
		IvParameterSpec iv = AESUtils.generateIv();
		SecretKey passwordKey = AESUtils.generateKeyFromPassword(password, salt, iteractions, AESUtils.KEY_LENGTH_256);
		byte[] encryptedBytes = AESUtils.encrypt(AESUtils.ALGORITHM_OFB, passwordKey, iv, inputBytes);
		String encryptedString = AESUtils.encryptToString(AESUtils.ALGORITHM_OFB, passwordKey, iv, inputBytes);
		String decryptedString1 = AESUtils.decryptToString(AESUtils.ALGORITHM_OFB, passwordKey, iv, encryptedBytes);
		String decryptedString2 = AESUtils.decryptToString(AESUtils.ALGORITHM_OFB, passwordKey, iv, encryptedString);
		Assertions.assertEquals(inputString, decryptedString1);
		Assertions.assertEquals(inputString, decryptedString2);
		Assertions.assertArrayEquals(inputBytes, decryptedString1.getBytes(encoding));
		Assertions.assertArrayEquals(inputBytes, decryptedString2.getBytes(encoding));
	}
	
	@Test
	void fromStringToByteWithPasswordKey() throws Exception {
		IvParameterSpec iv = AESUtils.generateIv();
		SecretKey passwordKey = AESUtils.generateKeyFromPassword(password, salt, iteractions, AESUtils.KEY_LENGTH_256);
		byte[] encryptedBytes = AESUtils.encrypt(AESUtils.ALGORITHM_OFB, passwordKey, iv, inputString);
		String encryptedString = AESUtils.encryptToString(AESUtils.ALGORITHM_OFB, passwordKey, iv, inputString);
		byte[] decryptedBytes1 = AESUtils.decrypt(AESUtils.ALGORITHM_OFB, passwordKey, iv, encryptedBytes);
		byte[] decryptedBytes2 = AESUtils.decrypt(AESUtils.ALGORITHM_OFB, passwordKey, iv, encryptedString);
		Assertions.assertEquals(inputString, new String(decryptedBytes1, encoding));
		Assertions.assertEquals(inputString, new String(decryptedBytes2, encoding));
		Assertions.assertArrayEquals(inputString.getBytes(encoding), decryptedBytes1);
		Assertions.assertArrayEquals(inputString.getBytes(encoding), decryptedBytes2);
	}
	
	@Test
	void fromStringToStringWithPasswordKey() throws Exception {
		IvParameterSpec iv = AESUtils.generateIv();
		SecretKey passwordKey = AESUtils.generateKeyFromPassword(password, salt, iteractions, AESUtils.KEY_LENGTH_256);
		byte[] encryptedBytes = AESUtils.encrypt(AESUtils.ALGORITHM_OFB, passwordKey, iv, inputString);
		String encryptedString = AESUtils.encryptToString(AESUtils.ALGORITHM_OFB, passwordKey, iv, inputString);
		String decryptedString1 = AESUtils.decryptToString(AESUtils.ALGORITHM_OFB, passwordKey, iv, encryptedBytes);
		String decryptedString2 = AESUtils.decryptToString(AESUtils.ALGORITHM_OFB, passwordKey, iv, encryptedString);
		Assertions.assertEquals(inputString, decryptedString1);
		Assertions.assertEquals(inputString, decryptedString2);
	}
	
	private String getTestName(TestInfo info) {
		return info.getDisplayName().substring(0, info.getDisplayName().length() - 2);
	}
}
