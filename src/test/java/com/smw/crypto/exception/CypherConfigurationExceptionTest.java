package com.smw.crypto.exception;

import java.security.NoSuchAlgorithmException;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.smw.crypto.BaseCryptoTest;

class CypherConfigurationExceptionTest extends BaseCryptoTest {
	
	private final String message = "message";
	private final Throwable throwable = new NoSuchAlgorithmException(message);
	
	@BeforeEach
	void printVariables() {
		log.info("message = {}", message);
		log.info("throwable = {}", throwable.toString());
	}
	
	@Test
	void withMessage() throws Exception {
		CypherConfigurationException exception = new CypherConfigurationException(message);
		Assertions.assertEquals(exception.getMessage(), message);
	}

	@Test
	void withThrowable() throws Exception {
		CypherConfigurationException exception = new CypherConfigurationException(throwable);
		Assertions.assertEquals(exception.getCause(), throwable);
		Assertions.assertEquals(exception.getCause().getMessage(), throwable.getMessage());
	}
}
