package com.smw.crypto.core;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * Utility static class grouping common constants:
 * <ul>
 * <li>SecureRandomProviders</li>
 * <li>SecureRandomAlgorithms</li>
 * </ul>
 */
public class Constants {

	public static final Charset DEFAULT_CHARSET = StandardCharsets.UTF_8;
	public static final String DEFAULT_SYMMETRIC_PASSWORD_ALGORITHM = "PBKDF2WithHmacSHA256";
	
	private Constants() {}
	
	/**
	 * Listing of supported secure random providers
	 */
	public enum SecureRandomProviders {
		
		SUN("SUN");
		
		private final String value;
		
		private SecureRandomProviders(String value) {
			this.value = value;
		}
		
		public String value() {
			return this.value;
		}
	}
	
	/**
	 * Listing of supported secure random algorithms
	 */
	public enum SecureRandomAlgorithms {
		
		SHA1PRNG("SHA1PRNG");
		
		private final String value;
		
		private SecureRandomAlgorithms(String value) {
			this.value = value;
		}
		
		public String value() {
			return this.value;
		}
	}
}
