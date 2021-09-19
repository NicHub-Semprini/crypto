package com.smw.crypto.aes;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class AESUtils {

	public static final String ALGORITHM = "AES";
	public static final String PASSWORD_ALGORITHM = "PBKDF2WithHmacSHA256";
	public static final int IV_LENGTH = 16;
	public static final int KEY_LENGTH_128 = 128;
	public static final int KEY_LENGTH_192 = 192;
	public static final int KEY_LENGTH_256 = 256;

	private AESUtils() {
	}

	public static SecretKey generateKey(int keyLength) throws NoSuchAlgorithmException {
		KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
		keyGenerator.init(keyLength);
		return keyGenerator.generateKey();
	}

	public static SecretKey getKeyFromPassword(String password, String salt, int iteractions, int keyLength)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		SecretKeyFactory factory = SecretKeyFactory.getInstance(PASSWORD_ALGORITHM);
		KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), iteractions, keyLength);
		return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), ALGORITHM);
	}

	public static IvParameterSpec generateIv() {
		byte[] iv = new byte[IV_LENGTH];
		new SecureRandom().nextBytes(iv);
		return new IvParameterSpec(iv);
	}

	public static IvParameterSpec generateIv(byte[] seed) {
		byte[] iv = new byte[IV_LENGTH];
		new SecureRandom(seed).nextBytes(iv);
		return new IvParameterSpec(iv);
	}
	
	// encrypt

	public static String encryptToString(String algorithm, SecretKey key, IvParameterSpec iv, String input,
			Charset charset) throws NoSuchPaddingException, NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		return encryptToString(algorithm, key, iv, input.getBytes(charset));
	}

	public static String encryptToString(String algorithm, SecretKey key, IvParameterSpec iv, String input)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		return encryptToString(algorithm, key, iv, input, StandardCharsets.UTF_8);
	}

	public static String encryptToString(String algorithm, SecretKey key, IvParameterSpec iv, byte[] input,
			Charset charset) throws NoSuchPaddingException, NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		return new String(Base64.getEncoder().encode(encrypt(algorithm, key, iv, input)), charset);
	}

	public static String encryptToString(String algorithm, SecretKey key, IvParameterSpec iv, byte[] input)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		return encryptToString(algorithm, key, iv, input, StandardCharsets.UTF_8);
	}
	
	public static byte[] encrypt(String algorithm, SecretKey key, IvParameterSpec iv, String input,
			Charset charset) throws NoSuchPaddingException, NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		return encrypt(algorithm, key, iv, input.getBytes(charset));
	}

	public static byte[] encrypt(String algorithm, SecretKey key, IvParameterSpec iv, String input)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		return encrypt(algorithm, key, iv, input, StandardCharsets.UTF_8);
	}

	public static byte[] encrypt(String algorithm, SecretKey key, IvParameterSpec iv, byte[] input)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		Cipher cipher = Cipher.getInstance(algorithm);
		cipher.init(Cipher.ENCRYPT_MODE, key, iv);
		return cipher.doFinal(input);
	}

	// decrypt
	
	public static String decryptToString(String algorithm, SecretKey key, IvParameterSpec iv, String base64String,
			Charset charset) throws NoSuchPaddingException, NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		return new String(decrypt(algorithm, key, iv, Base64.getDecoder().decode(base64String.getBytes(charset))));
	}

	public static String decryptToString(String algorithm, SecretKey key, IvParameterSpec iv, String base64String)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		return decryptToString(algorithm, key, iv, base64String, StandardCharsets.UTF_8);
	}

	public static String decryptToString(String algorithm, SecretKey key, IvParameterSpec iv, byte[] input, Charset charset)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		return new String(decrypt(algorithm, key, iv, input), charset);
	}
	
	public static String decryptToString(String algorithm, SecretKey key, IvParameterSpec iv, byte[] input)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		return new String(decrypt(algorithm, key, iv, input), StandardCharsets.UTF_8);
	}

	public static byte[] decrypt(String algorithm, SecretKey key, IvParameterSpec iv, String base64String,
			Charset charset) throws NoSuchPaddingException, NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		return decrypt(algorithm, key, iv, Base64.getDecoder().decode(base64String.getBytes(charset)));
	}

	public static byte[] decrypt(String algorithm, SecretKey key, IvParameterSpec iv, String base64String)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		return decrypt(algorithm, key, iv, base64String, StandardCharsets.UTF_8);
	}

	public static byte[] decrypt(String algorithm, SecretKey key, IvParameterSpec iv, byte[] input)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		Cipher cipher = Cipher.getInstance(algorithm);
		cipher.init(Cipher.DECRYPT_MODE, key, iv);
		return cipher.doFinal(input);
	}
}
