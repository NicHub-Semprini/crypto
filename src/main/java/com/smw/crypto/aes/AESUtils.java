package com.smw.crypto.aes;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
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

	public static final String ALGORITHM_FAMILY = "AES";
	public static final String PASSWORD_ALGORITHM = "PBKDF2WithHmacSHA256";
	public static final String ALGORITHM_OFB = "AES/OFB32/PKCS5Padding";
	public static final int IV_LENGTH = 16;
	public static final int KEY_LENGTH_128 = 128;
	public static final int KEY_LENGTH_192 = 192;
	public static final int KEY_LENGTH_256 = 256;
	public static final String SECURE_RANDOM_ALGORITHM = "SHA1PRNG";
	public static final String SECURE_RANDOM_PROVIDER = "SUN";
	public static final Charset DEFAULT_CHARSET = StandardCharsets.UTF_8;

	private AESUtils() {}

	// TODO javadoc	
	/**
	 * 
	 * @param keyLength
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static SecretKey generateRandomKey(int keyLength)
			throws NoSuchAlgorithmException {
		KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM_FAMILY);
		keyGenerator.init(keyLength);
		return keyGenerator.generateKey();
	}

	// TODO javadoc
	/**
	 * 
	 * @param password
	 * @param salt
	 * @param iteractions
	 * @param keyLength
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	public static SecretKey generateKeyFromPassword(String password, String salt, int iteractions, int keyLength)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		SecretKeyFactory factory = SecretKeyFactory.getInstance(PASSWORD_ALGORITHM);
		KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), iteractions, keyLength);
		return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), ALGORITHM_FAMILY);
	}

	// TODO javadoc
	/**
	 * 
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 */
	public static IvParameterSpec generateIv()
			throws NoSuchAlgorithmException, NoSuchProviderException {
		byte[] iv = new byte[IV_LENGTH];
		SecureRandom.getInstance(SECURE_RANDOM_ALGORITHM, SECURE_RANDOM_PROVIDER).nextBytes(iv);
		return new IvParameterSpec(iv);
	}

	// TODO javadoc
	/**
	 * 
	 * @param seed
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 */
	public static IvParameterSpec generateIv(byte[] seed)
			throws NoSuchAlgorithmException, NoSuchProviderException {
		byte[] iv = new byte[IV_LENGTH];
		SecureRandom secureRandom = SecureRandom.getInstance(SECURE_RANDOM_ALGORITHM, SECURE_RANDOM_PROVIDER);
		secureRandom.setSeed(seed);
		secureRandom.nextBytes(iv);
		return new IvParameterSpec(iv);
	}
	
	// TODO javadoc
	/**
	 * stringa-stringa base64 con encoding input != output
	 * @param algorithm
	 * @param key
	 * @param iv
	 * @param input
	 * @param inputCharset
	 * @param outputCharset
	 * @return 
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	public static String encryptToString(String algorithm, SecretKey key, IvParameterSpec iv, String input, Charset inputCharset, Charset outputCharset)
			throws NoSuchPaddingException, NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		return encryptToString(algorithm, key, iv, input.getBytes(inputCharset), outputCharset);
	}
	
	// TODO javadoc
	/**
	 * stringa-stringa base64 con encoding input = output
	 * @param algorithm
	 * @param key
	 * @param iv
	 * @param input
	 * @param charset
	 * @return
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	public static String encryptToString(String algorithm, SecretKey key, IvParameterSpec iv, String input, Charset charset)
			throws NoSuchPaddingException, NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		return encryptToString(algorithm, key, iv, input, charset, charset);
	}

	// TODO javadoc
	/**
	 * stringa-stringa base64 con encoding input = output = DEFAULT_ENCODING
	 * @param algorithm
	 * @param key
	 * @param iv
	 * @param input
	 * @return
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	public static String encryptToString(String algorithm, SecretKey key, IvParameterSpec iv, String input)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		return encryptToString(algorithm, key, iv, input, DEFAULT_CHARSET);
	}

	// TODO javadoc
	/**
	 * byte-stringa base64 con encoding output = DEFAULT_ENCODING
	 * @param algorithm
	 * @param key
	 * @param iv
	 * @param input
	 * @return
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	public static String encryptToString(String algorithm, SecretKey key, IvParameterSpec iv, byte[] input)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		return encryptToString(algorithm, key, iv, input, DEFAULT_CHARSET);
	}
	
	// TODO javadoc
	/**
	 * byte-stringa versione base
	 * @param algorithm
	 * @param key
	 * @param iv
	 * @param input
	 * @param charset
	 * @return
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	public static String encryptToString(String algorithm, SecretKey key, IvParameterSpec iv, byte[] input, Charset charset)
			throws NoSuchPaddingException, NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		return new String(Base64.getEncoder().encode(encrypt(algorithm, key, iv, input)), charset);
	}

	// TODO javadoc
	/**
	 * stringa-byte con encoding output
	 * @param algorithm
	 * @param key
	 * @param iv
	 * @param input
	 * @param charset
	 * @return
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	public static byte[] encrypt(String algorithm, SecretKey key, IvParameterSpec iv, String input, Charset charset)
			throws NoSuchPaddingException, NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		return encrypt(algorithm, key, iv, input.getBytes(charset));
	}

	// TODO javadoc
	/**
	 * stringa-byte con encoding output = DEFAULT_ENCODING
	 * @param algorithm
	 * @param key
	 * @param iv
	 * @param input
	 * @return
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	public static byte[] encrypt(String algorithm, SecretKey key, IvParameterSpec iv, String input)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		return encrypt(algorithm, key, iv, input, DEFAULT_CHARSET);
	}

	// TODO javadoc
	/**
	 * byte-byte versione base
	 * @param algorithm
	 * @param key
	 * @param iv
	 * @param input
	 * @return
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	public static byte[] encrypt(String algorithm, SecretKey key, IvParameterSpec iv, byte[] input)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		Cipher cipher = Cipher.getInstance(algorithm);
		cipher.init(Cipher.ENCRYPT_MODE, key, iv);
		return cipher.doFinal(input);
	}

	// TODO javadoc
	/**
	 * stringa-stringa con encoding input != output
	 * @param algorithm
	 * @param key
	 * @param iv
	 * @param base64String
	 * @param inputCharset
	 * @param outputCharset
	 * @return
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	public static String decryptToString(String algorithm, SecretKey key, IvParameterSpec iv, String base64String, Charset inputCharset, Charset outputCharset)
			throws NoSuchPaddingException, NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		return decryptToString(algorithm, key, iv, Base64.getDecoder().decode(base64String.getBytes(inputCharset)), outputCharset);
	}
	
	// TODO javadoc
	/**
	 * stringa-stringa con encoding input = output
	 * @param algorithm
	 * @param key
	 * @param iv
	 * @param base64String
	 * @param charset
	 * @return
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	public static String decryptToString(String algorithm, SecretKey key, IvParameterSpec iv, String base64String, Charset charset)
			throws NoSuchPaddingException, NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		return decryptToString(algorithm, key, iv, base64String, charset, charset);
	}

	// TODO javadoc
	/**
	 * stringa-stringa con encoding input = output = DEFAULT_ENCODING
	 * @param algorithm
	 * @param key
	 * @param iv
	 * @param base64String
	 * @return
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	public static String decryptToString(String algorithm, SecretKey key, IvParameterSpec iv, String base64String)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		return decryptToString(algorithm, key, iv, base64String, DEFAULT_CHARSET);
	}

	// TODO javadoc
	/**
	 * byte-stringa con encoding output
	 * @param algorithm
	 * @param key
	 * @param iv
	 * @param input
	 * @param charset
	 * @return
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	public static String decryptToString(String algorithm, SecretKey key, IvParameterSpec iv, byte[] input, Charset charset)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		return new String(decrypt(algorithm, key, iv, input), charset);
	}
	
	// TODO javadoc
	/**
	 * byte-stringa con encoding output = DEFAULT_ENCODING
	 * @param algorithm
	 * @param key
	 * @param iv
	 * @param input
	 * @return
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	public static String decryptToString(String algorithm, SecretKey key, IvParameterSpec iv, byte[] input)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		return decryptToString(algorithm, key, iv, input, DEFAULT_CHARSET);
	}

	// TODO javadoc
	/**
	 * stringa-byte con encoding input
	 * @param algorithm
	 * @param key
	 * @param iv
	 * @param base64String
	 * @param charset
	 * @return
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	public static byte[] decrypt(String algorithm, SecretKey key, IvParameterSpec iv, String base64String, Charset charset)
			throws NoSuchPaddingException, NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		return decrypt(algorithm, key, iv, Base64.getDecoder().decode(base64String.getBytes(charset)));
	}

	// TODO javadoc
	/**
	 * stringa-byte con encoding input
	 * @param algorithm
	 * @param key
	 * @param iv
	 * @param base64String
	 * @return
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	public static byte[] decrypt(String algorithm, SecretKey key, IvParameterSpec iv, String base64String)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		return decrypt(algorithm, key, iv, base64String, DEFAULT_CHARSET);
	}

	// TODO javadoc
	/**
	 * byte-byte versione base
	 * @param algorithm
	 * @param key
	 * @param iv
	 * @param input
	 * @return
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	public static byte[] decrypt(String algorithm, SecretKey key, IvParameterSpec iv, byte[] input)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		Cipher cipher = Cipher.getInstance(algorithm);
		cipher.init(Cipher.DECRYPT_MODE, key, iv);
		return cipher.doFinal(input);
	}
}
