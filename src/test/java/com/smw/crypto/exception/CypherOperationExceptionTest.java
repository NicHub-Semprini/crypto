package com.smw.crypto.exception;

import java.security.NoSuchAlgorithmException;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.smw.crypto.BaseCryptoTest;

class CypherOperationExceptionTest extends BaseCryptoTest {
	
	private final String message = "message";
	private final Throwable throwable = new NoSuchAlgorithmException(message);
	
	@BeforeEach
	void printVariables() {
		log.info("message = {}", message);
		log.info("throwable = {}", throwable.toString());
	}
	
	@Test
	void withMessage() throws Exception {
		CypherOperationException exception = new CypherOperationException(message);
		Assertions.assertEquals(exception.getMessage(), message);
	}

	@Test
	void withThrowable() throws Exception {
		CypherOperationException exception = new CypherOperationException(throwable);
		Assertions.assertEquals(exception.getCause(), throwable);
		Assertions.assertEquals(exception.getCause().getMessage(), throwable.getMessage());
	}
}
