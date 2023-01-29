package com.smw.crypto.implementation.aes;

/**
 * Utility static class grouping AES constants:
 * <ul>
 * <li>ALGORITHM_FAMILY = {@value AESConstants#ALGORITHM_FAMILY}</li>
 * <li>PASSWORD_ALGORITHM = {@value AESConstants#PASSWORD_ALGORITHM}</li>
 * <li>IV_LENGTH = {@value AESConstants#IV_LENGTH}</li>
 * <li>AlgorithmImplementations</li>
 * <li>KeyLengths</li>
 * </ul>
 */
public class AESConstants {

	public static final String ALGORITHM_FAMILY = "AES";
	
	private AESConstants() {}
	
	/**
	 * Listing of supported algorithm implementations
	 */
	public enum AlgorithmImplementations {
		CBC("AES/CBC/PKCS5Padding"),
		CFB("AES/CFB/PKCS5Padding"),
		CFB32("AES/CFB32/PKCS5Padding"),
		ECB("AES/ECB/PKCS5Padding"),
		OFB("AES/OFB/PKCS5Padding"),
		OFB32("AES/OFB32/PKCS5Padding"),
		PCBC("AES/PCBC/PKCS5Padding");
		
		private final String value;
		
		private AlgorithmImplementations(String value) {
			this.value = value;
		}
		
		public String value() {
			return this.value;
		}
	}

	/**
	 * Listing of supported initialization vector (iv) lengths
	 */
	public enum IvLengths {
		IV_0(0),
		IV_16(16);
		
		private final int value;
		
		private IvLengths(int value) {
			this.value = value;
		}
		
		public int value() {
			return this.value;
		}
	}

	/**
	 * Listing of supported encryption/decryption key lengths
	 */
	public enum KeyLengths {
		KEY_128(128),
		KEY_192(192),
		KEY_256(256);
		
		private final int value;
		
		private KeyLengths(int value) {
			this.value = value;
		}
		
		public int value() {
			return this.value;
		}
	}
}
