package com.smw.crypto.aes;

import java.nio.charset.StandardCharsets;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class AESUtilsTest {

	@Test
	void givenString_whenEncrypt_thenSuccess() throws Exception {
		String input = "falco";
		String password = "pwd";
		String salt = "salt";
		byte[] seed = "seed".getBytes(StandardCharsets.UTF_8);
		SecretKey key = AESUtils.getKeyFromPassword(password, salt, 65536, AESUtils.KEY_LENGTH_256);
//		IvParameterSpec ivParameterSpec = AESUtils.generateIv();
		IvParameterSpec ivParameterSpec = AESUtils.generateIv(seed);
		String algorithm = "AES/OFB32/PKCS5Padding";
		String cipherText = AESUtils.encryptToString(algorithm, key, ivParameterSpec, input);
		String plainText = AESUtils.decryptToString(algorithm, key, ivParameterSpec, cipherText);
		Assertions.assertEquals(input, plainText);
	}
}
