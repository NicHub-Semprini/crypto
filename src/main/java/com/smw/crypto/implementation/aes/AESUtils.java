package com.smw.crypto.implementation.aes;

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

import com.smw.crypto.core.Constants;
import com.smw.crypto.core.Constants.SecureRandomAlgorithms;
import com.smw.crypto.core.Constants.SecureRandomProviders;
import com.smw.crypto.implementation.aes.AESConstants.AlgorithmImplementations;
import com.smw.crypto.implementation.aes.AESConstants.IvLengths;
import com.smw.crypto.implementation.aes.AESConstants.KeyLengths;

/**
 * Utility static class to encrypt and decrypt string and bytes using AES algorithms<br/>
 * <br/>
 * <b>Static variables:</b>
 * <ul>
 * <li>ALGORITHM_FAMILY = {@value AESUtils#ALGORITHM_FAMILY}</li>
 * <li>PASSWORD_ALGORITHM = {@value AESUtils#PASSWORD_ALGORITHM}</li>
 * <li>IV_LENGTH = {@link IvLengths#IV_16}</li> 
 * <li>SECURE_RANDOM_ALGORITHM = {@link SecureRandomAlgorithms#SHA1PRNG}</li>
 * <li>SECURE_RANDOM_PROVIDER = {@link SecureRandomProviders#SUN}</li>
 * <li>DEFAULT_CHARSET = {@link StandardCharsets#UTF_8}</li>
 * </ul>
 */
public class AESUtils {

	public static final String ALGORITHM_FAMILY = AESConstants.ALGORITHM_FAMILY;
	public static final String PASSWORD_ALGORITHM = Constants.DEFAULT_SYMMETRIC_PASSWORD_ALGORITHM;
	public static final IvLengths IV_LENGTH = IvLengths.IV_16;
	public static final SecureRandomAlgorithms SECURE_RANDOM_ALGORITHM = SecureRandomAlgorithms.SHA1PRNG;
	public static final SecureRandomProviders SECURE_RANDOM_PROVIDER = SecureRandomProviders.SUN;
	public static final Charset DEFAULT_CHARSET = Constants.DEFAULT_CHARSET;

	private AESUtils() {}
	

	/**
	 * Generates a brand new random key
	 * @param keyLength the length (in bytes) of the key to generate
	 * @return the generated key
	 * @throws NoSuchAlgorithmException if {@value AESUtils#ALGORITHM_FAMILY} algorithm family isn't supported 
	 */
	public static SecretKey generateRandomKey(KeyLengths keyLength)
			throws NoSuchAlgorithmException {
		KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM_FAMILY);
		keyGenerator.init(keyLength.value());
		return keyGenerator.generateKey();
	}

	/**
	 * Generates a brand new random key using {@value AESUtils#PASSWORD_ALGORITHM} as password algorithm
	 * @param password key generator initialization password
	 * @param salt key generator initialization vector
	 * @param iteractions number of iterations during generation process
	 * @param keyLength the length (in bytes) of the key to generate
	 * @return the generated key
	 * @throws NoSuchAlgorithmException if {@value AESUtils#PASSWORD_ALGORITHM} algorithm isn't supported 
	 * @throws InvalidKeySpecException if {@value AESUtils#ALGORITHM_FAMILY} algorithm family isn't supported 
	 */
	public static SecretKey generateKeyFromPassword(String password, String salt, int iteractions, KeyLengths keyLength)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		return generateKeyFromPassword(PASSWORD_ALGORITHM, password, salt, iteractions, keyLength);
	}

	/**
	 * Generates a brand new random key
	 * @param passwordAlgorithm secret key factory algorithm
	 * @param password key generator initialization password
	 * @param salt key generator initialization vector
	 * @param iteractions number of iterations during generation process
	 * @param keyLength the length (in bytes) of the key to generate
	 * @return the generated key
	 * @throws NoSuchAlgorithmException if the given password algorithm isn't supported 
	 * @throws InvalidKeySpecException if {@value AESUtils#ALGORITHM_FAMILY} algorithm family isn't supported 
	 */
	public static SecretKey generateKeyFromPassword(String passwordAlgorithm, String password, String salt, int iteractions, KeyLengths keyLength)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		SecretKeyFactory factory = SecretKeyFactory.getInstance(passwordAlgorithm);
		KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), iteractions, keyLength.value());
		return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), ALGORITHM_FAMILY);
	}

	/**
	 * Generates a brand new random initialization vector (iv) of {@link AESUtils#IV_LENGTH} bytes
	 * @return the generated vector
	 * @throws NoSuchAlgorithmException if {@link AESUtils#SECURE_RANDOM_ALGORITHM} algorithm isn't supported by {@link AESUtils#SECURE_RANDOM_PROVIDER} provider
	 * @throws NoSuchProviderException if {@link AESUtils#SECURE_RANDOM_PROVIDER} provider isn't supported
	 */
	public static IvParameterSpec generateIv()
			throws NoSuchAlgorithmException, NoSuchProviderException {
		byte[] iv = new byte[IV_LENGTH.value()];
		SecureRandom.getInstance(SECURE_RANDOM_ALGORITHM.value(), SECURE_RANDOM_PROVIDER.value()).nextBytes(iv);
		return new IvParameterSpec(iv);
	}

	/**
	 * Generates a brand new random initialization vector (iv) of {@link AESUtils#IV_LENGTH} bytes
	 * @param seed the seed used for vector generation
	 * @return the generated vector
	 * @throws NoSuchAlgorithmException if {@link AESUtils#SECURE_RANDOM_ALGORITHM} algorithm isn't supported by {@link AESUtils#SECURE_RANDOM_PROVIDER} provider
	 * @throws NoSuchProviderException if {@link AESUtils#SECURE_RANDOM_PROVIDER} provider isn't supported
	 */
	public static IvParameterSpec generateIv(byte[] seed)
			throws NoSuchAlgorithmException, NoSuchProviderException {
		byte[] iv = new byte[IV_LENGTH.value()];
		SecureRandom secureRandom = SecureRandom.getInstance(SECURE_RANDOM_ALGORITHM.value(), SECURE_RANDOM_PROVIDER.value());
		secureRandom.setSeed(seed);
		secureRandom.nextBytes(iv);
		return new IvParameterSpec(iv);
	}
	
	/**
	 * Encrypts given base64-encoded input string producing a base64-encoded output string
	 * @param algorithm the encryption algorithm
	 * @param key the encryption {@link SecretKey}
	 * @param iv the encryption {@link IvParameterSpec}
	 * @param input the base64-encoded string to encrypt
	 * @param inputCharset the input string {@link Charset}
	 * @param outputCharset the output string {@link Charset}
	 * @return the base64-encoded encrypted string
	 * @throws NoSuchPaddingException by the underlying {@link Cipher}
	 * @throws NoSuchAlgorithmException by the underlying {@link Cipher}
	 * @throws InvalidAlgorithmParameterException by the underlying {@link Cipher}
	 * @throws InvalidKeyException by the underlying {@link Cipher}
	 * @throws BadPaddingException by the underlying {@link Cipher}
	 * @throws IllegalBlockSizeException by the underlying {@link Cipher}
	 */
	public static String encryptToString(AlgorithmImplementations algorithm, SecretKey key, IvParameterSpec iv, String input, Charset inputCharset, Charset outputCharset)
			throws NoSuchPaddingException, NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		return encryptToString(algorithm, key, iv, input.getBytes(inputCharset), outputCharset);
	}
	
	/**
	 * Encrypts given base64-encoded input string producing a base64-encoded output string
	 * @param algorithm the encryption algorithm
	 * @param key the encryption {@link SecretKey}
	 * @param iv the encryption {@link IvParameterSpec}
	 * @param input the base64-encoded string to encrypt
	 * @param charset the input and output strings {@link Charset}
	 * @return the base64-encoded encrypted string
	 * @throws NoSuchPaddingException by the underlying {@link Cipher}
	 * @throws NoSuchAlgorithmException by the underlying {@link Cipher}
	 * @throws InvalidAlgorithmParameterException by the underlying {@link Cipher}
	 * @throws InvalidKeyException by the underlying {@link Cipher}
	 * @throws BadPaddingException by the underlying {@link Cipher}
	 * @throws IllegalBlockSizeException by the underlying {@link Cipher}
	 */
	public static String encryptToString(AlgorithmImplementations algorithm, SecretKey key, IvParameterSpec iv, String input, Charset charset)
			throws NoSuchPaddingException, NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		return encryptToString(algorithm, key, iv, input, charset, charset);
	}

	/**
	 * Encrypts given UTF-8 base64-encoded input string producing an UTF-8 base64-encoded output string
	 * @param algorithm the encryption algorithm
	 * @param key the encryption {@link SecretKey}
	 * @param iv the encryption {@link IvParameterSpec}
	 * @param input the UTF-8 base64-encoded string to encrypt
	 * @return the UTF-8 base64-encoded encrypted string
	 * @throws NoSuchPaddingException by the underlying {@link Cipher}
	 * @throws NoSuchAlgorithmException by the underlying {@link Cipher}
	 * @throws InvalidAlgorithmParameterException by the underlying {@link Cipher}
	 * @throws InvalidKeyException by the underlying {@link Cipher}
	 * @throws BadPaddingException by the underlying {@link Cipher}
	 * @throws IllegalBlockSizeException by the underlying {@link Cipher}
	 */
	public static String encryptToString(AlgorithmImplementations algorithm, SecretKey key, IvParameterSpec iv, String input)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		return encryptToString(algorithm, key, iv, input, DEFAULT_CHARSET);
	}

	/**
	 * Encrypts given bytes producing an UTF-8 base64-encoded string
	 * @param algorithm the encryption algorithm
	 * @param key the encryption {@link SecretKey}
	 * @param iv the encryption {@link IvParameterSpec}
	 * @param input the bytes to encrypt
	 * @return the UTF-8 base64-encoded encrypted string
	 * @throws NoSuchPaddingException by the underlying {@link Cipher}
	 * @throws NoSuchAlgorithmException by the underlying {@link Cipher}
	 * @throws InvalidAlgorithmParameterException by the underlying {@link Cipher}
	 * @throws InvalidKeyException by the underlying {@link Cipher}
	 * @throws BadPaddingException by the underlying {@link Cipher}
	 * @throws IllegalBlockSizeException by the underlying {@link Cipher}
	 */
	public static String encryptToString(AlgorithmImplementations algorithm, SecretKey key, IvParameterSpec iv, byte[] input)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		return encryptToString(algorithm, key, iv, input, DEFAULT_CHARSET);
	}
	
	/**
	 * Encrypts given bytes producing a base64-encoded string
	 * @param algorithm the encryption algorithm
	 * @param key the encryption {@link SecretKey}
	 * @param iv the encryption {@link IvParameterSpec}
	 * @param input the bytes to encrypt
	 * @param charset the string {@link Charset}
	 * @return the base64-encoded encrypted string
	 * @throws NoSuchPaddingException by the underlying {@link Cipher}
	 * @throws NoSuchAlgorithmException by the underlying {@link Cipher}
	 * @throws InvalidAlgorithmParameterException by the underlying {@link Cipher}
	 * @throws InvalidKeyException by the underlying {@link Cipher}
	 * @throws BadPaddingException by the underlying {@link Cipher}
	 * @throws IllegalBlockSizeException by the underlying {@link Cipher}
	 */
	public static String encryptToString(AlgorithmImplementations algorithm, SecretKey key, IvParameterSpec iv, byte[] input, Charset charset)
			throws NoSuchPaddingException, NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		return new String(Base64.getEncoder().encode(encrypt(algorithm, key, iv, input)), charset);
	}

	/**
	 * Encrypts given base64-encoded string producing bytes
	 * @param algorithm the encryption algorithm
	 * @param key the encryption {@link SecretKey}
	 * @param iv the encryption {@link IvParameterSpec}
	 * @param input the base64-encoded string to encrypt
	 * @param charset the string {@link Charset}
	 * @return the encrypted bytes
	 * @throws NoSuchPaddingException by the underlying {@link Cipher}
	 * @throws NoSuchAlgorithmException by the underlying {@link Cipher}
	 * @throws InvalidAlgorithmParameterException by the underlying {@link Cipher}
	 * @throws InvalidKeyException by the underlying {@link Cipher}
	 * @throws BadPaddingException by the underlying {@link Cipher}
	 * @throws IllegalBlockSizeException by the underlying {@link Cipher}
	 */
	public static byte[] encrypt(AlgorithmImplementations algorithm, SecretKey key, IvParameterSpec iv, String input, Charset charset)
			throws NoSuchPaddingException, NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		return encrypt(algorithm, key, iv, input.getBytes(charset));
	}

	/**
	 * Encrypts given UTF-8 base64-encoded string producing bytes
	 * @param algorithm the encryption algorithm
	 * @param key the encryption {@link SecretKey}
	 * @param iv the encryption {@link IvParameterSpec}
	 * @param input the base64-encoded string to encrypt
	 * @return the encrypted bytes
	 * @throws NoSuchPaddingException by the underlying {@link Cipher}
	 * @throws NoSuchAlgorithmException by the underlying {@link Cipher}
	 * @throws InvalidAlgorithmParameterException by the underlying {@link Cipher}
	 * @throws InvalidKeyException by the underlying {@link Cipher}
	 * @throws BadPaddingException by the underlying {@link Cipher}
	 * @throws IllegalBlockSizeException by the underlying {@link Cipher}
	 */
	public static byte[] encrypt(AlgorithmImplementations algorithm, SecretKey key, IvParameterSpec iv, String input)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		return encrypt(algorithm, key, iv, input, DEFAULT_CHARSET);
	}

	/**
	 * Encrypts given input bytes producing output bytes
	 * @param algorithm the encryption algorithm
	 * @param key the encryption {@link SecretKey}
	 * @param iv the encryption {@link IvParameterSpec}
	 * @param input the bytes to encrypt
	 * @return the encrypted bytes
	 * @throws NoSuchPaddingException by the underlying {@link Cipher}
	 * @throws NoSuchAlgorithmException by the underlying {@link Cipher}
	 * @throws InvalidAlgorithmParameterException by the underlying {@link Cipher}
	 * @throws InvalidKeyException by the underlying {@link Cipher}
	 * @throws BadPaddingException by the underlying {@link Cipher}
	 * @throws IllegalBlockSizeException by the underlying {@link Cipher}
	 */
	public static byte[] encrypt(AlgorithmImplementations algorithm, SecretKey key, IvParameterSpec iv, byte[] input)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		Cipher cipher = Cipher.getInstance(algorithm.value());
		cipher.init(Cipher.ENCRYPT_MODE, key, iv);
		return cipher.doFinal(input);
	}

	/**
	 * Decrypts given base64-encoded input string producing an output string
	 * @param algorithm the encryption algorithm
	 * @param key the encryption {@link SecretKey}
	 * @param iv the encryption {@link IvParameterSpec}
	 * @param base64String the base64-encoded string to decrypt
	 * @param inputCharset the input string {@link Charset}
	 * @param outputCharset the output string {@link Charset}
	 * @return the decrypted string
	 * @throws NoSuchPaddingException by the underlying {@link Cipher}
	 * @throws NoSuchAlgorithmException by the underlying {@link Cipher}
	 * @throws InvalidAlgorithmParameterException by the underlying {@link Cipher}
	 * @throws InvalidKeyException by the underlying {@link Cipher}
	 * @throws BadPaddingException by the underlying {@link Cipher}
	 * @throws IllegalBlockSizeException by the underlying {@link Cipher}
	 */
	public static String decryptToString(AlgorithmImplementations algorithm, SecretKey key, IvParameterSpec iv, String base64String, Charset inputCharset, Charset outputCharset)
			throws NoSuchPaddingException, NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		return decryptToString(algorithm, key, iv, Base64.getDecoder().decode(base64String.getBytes(inputCharset)), outputCharset);
	}
	
	/**
	 * Decrypts given base64-encoded input string producing an output string
	 * @param algorithm the encryption algorithm
	 * @param key the encryption {@link SecretKey}
	 * @param iv the encryption {@link IvParameterSpec}
	 * @param base64String the base64-encoded string to decrypt
	 * @param charset the input and output strings {@link Charset}
	 * @return the decrypted string
	 * @throws NoSuchPaddingException by the underlying {@link Cipher}
	 * @throws NoSuchAlgorithmException by the underlying {@link Cipher}
	 * @throws InvalidAlgorithmParameterException by the underlying {@link Cipher}
	 * @throws InvalidKeyException by the underlying {@link Cipher}
	 * @throws BadPaddingException by the underlying {@link Cipher}
	 * @throws IllegalBlockSizeException by the underlying {@link Cipher}
	 */
	public static String decryptToString(AlgorithmImplementations algorithm, SecretKey key, IvParameterSpec iv, String base64String, Charset charset)
			throws NoSuchPaddingException, NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		return decryptToString(algorithm, key, iv, base64String, charset, charset);
	}

	/**
	 * Decrypts given UTF-8 base64-encoded input string producing an UTF-8 output string
	 * @param algorithm the encryption algorithm
	 * @param key the encryption {@link SecretKey}
	 * @param iv the encryption {@link IvParameterSpec}
	 * @param base64String the base64-encoded string to decrypt
	 * @return the decrypted string
	 * @throws NoSuchPaddingException by the underlying {@link Cipher}
	 * @throws NoSuchAlgorithmException by the underlying {@link Cipher}
	 * @throws InvalidAlgorithmParameterException by the underlying {@link Cipher}
	 * @throws InvalidKeyException by the underlying {@link Cipher}
	 * @throws BadPaddingException by the underlying {@link Cipher}
	 * @throws IllegalBlockSizeException by the underlying {@link Cipher}
	 */
	public static String decryptToString(AlgorithmImplementations algorithm, SecretKey key, IvParameterSpec iv, String base64String)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		return decryptToString(algorithm, key, iv, base64String, DEFAULT_CHARSET);
	}

	/**
	 * Decrypts given bytes producing a string
	 * @param algorithm the encryption algorithm
	 * @param key the encryption {@link SecretKey}
	 * @param iv the encryption {@link IvParameterSpec}
	 * @param input the bytes to decrypt
	 * @param charset the string {@link Charset}
	 * @return the decrypted string
	 * @throws NoSuchPaddingException by the underlying {@link Cipher}
	 * @throws NoSuchAlgorithmException by the underlying {@link Cipher}
	 * @throws InvalidAlgorithmParameterException by the underlying {@link Cipher}
	 * @throws InvalidKeyException by the underlying {@link Cipher}
	 * @throws BadPaddingException by the underlying {@link Cipher}
	 * @throws IllegalBlockSizeException by the underlying {@link Cipher}
	 */
	public static String decryptToString(AlgorithmImplementations algorithm, SecretKey key, IvParameterSpec iv, byte[] input, Charset charset)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		return new String(decrypt(algorithm, key, iv, input), charset);
	}
	
	/**
	 * Decrypts given bytes producing an UTF-8 string
	 * @param algorithm the encryption algorithm
	 * @param key the encryption {@link SecretKey}
	 * @param iv the encryption {@link IvParameterSpec}
	 * @param input the bytes to decrypt
	 * @return the decrypted string
	 * @throws NoSuchPaddingException by the underlying {@link Cipher}
	 * @throws NoSuchAlgorithmException by the underlying {@link Cipher}
	 * @throws InvalidAlgorithmParameterException by the underlying {@link Cipher}
	 * @throws InvalidKeyException by the underlying {@link Cipher}
	 * @throws BadPaddingException by the underlying {@link Cipher}
	 * @throws IllegalBlockSizeException by the underlying {@link Cipher}
	 */
	public static String decryptToString(AlgorithmImplementations algorithm, SecretKey key, IvParameterSpec iv, byte[] input)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		return decryptToString(algorithm, key, iv, input, DEFAULT_CHARSET);
	}

	/**
	 * Decrypts given base64-encoded string producing bytes
	 * @param algorithm the encryption algorithm
	 * @param key the encryption {@link SecretKey}
	 * @param iv the encryption {@link IvParameterSpec}
	 * @param base64String the base64-encoded string to decrypt
	 * @param charset the string {@link Charset}
	 * @return the decrypted bytes
	 * @throws NoSuchPaddingException by the underlying {@link Cipher}
	 * @throws NoSuchAlgorithmException by the underlying {@link Cipher}
	 * @throws InvalidAlgorithmParameterException by the underlying {@link Cipher}
	 * @throws InvalidKeyException by the underlying {@link Cipher}
	 * @throws BadPaddingException by the underlying {@link Cipher}
	 * @throws IllegalBlockSizeException by the underlying {@link Cipher}
	 */
	public static byte[] decrypt(AlgorithmImplementations algorithm, SecretKey key, IvParameterSpec iv, String base64String, Charset charset)
			throws NoSuchPaddingException, NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		return decrypt(algorithm, key, iv, Base64.getDecoder().decode(base64String.getBytes(charset)));
	}

	/**
	 * Decrypts given UTF-8 base64-encoded string producing bytes
	 * @param algorithm the encryption algorithm
	 * @param key the encryption {@link SecretKey}
	 * @param iv the encryption {@link IvParameterSpec}
	 * @param base64String the UTF-8 base64-encoded string to decrypt
	 * @return the decrypted bytes
	 * @throws NoSuchPaddingException by the underlying {@link Cipher}
	 * @throws NoSuchAlgorithmException by the underlying {@link Cipher}
	 * @throws InvalidAlgorithmParameterException by the underlying {@link Cipher}
	 * @throws InvalidKeyException by the underlying {@link Cipher}
	 * @throws BadPaddingException by the underlying {@link Cipher}
	 * @throws IllegalBlockSizeException by the underlying {@link Cipher}
	 */
	public static byte[] decrypt(AlgorithmImplementations algorithm, SecretKey key, IvParameterSpec iv, String base64String)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		return decrypt(algorithm, key, iv, base64String, DEFAULT_CHARSET);
	}

	/**
	 * Decrypts given input bytes producing output bytes
	 * @param algorithm the encryption algorithm
	 * @param key the encryption {@link SecretKey}
	 * @param iv the encryption {@link IvParameterSpec}
	 * @param input the bytes to decrypt
	 * @return the decrypted bytes
	 * @throws NoSuchPaddingException by the underlying {@link Cipher}
	 * @throws NoSuchAlgorithmException by the underlying {@link Cipher}
	 * @throws InvalidAlgorithmParameterException by the underlying {@link Cipher}
	 * @throws InvalidKeyException by the underlying {@link Cipher}
	 * @throws BadPaddingException by the underlying {@link Cipher}
	 * @throws IllegalBlockSizeException by the underlying {@link Cipher}
	 */
	public static byte[] decrypt(AlgorithmImplementations algorithm, SecretKey key, IvParameterSpec iv, byte[] input)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		Cipher cipher = Cipher.getInstance(algorithm.value());
		cipher.init(Cipher.DECRYPT_MODE, key, iv);
		return cipher.doFinal(input);
	}
}
