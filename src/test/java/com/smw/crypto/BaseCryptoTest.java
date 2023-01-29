package com.smw.crypto;

import java.lang.reflect.Field;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.TestInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class BaseCryptoTest {

	protected final Logger log = LoggerFactory.getLogger(this.getClass());
	protected final ZoneOffset zoneOffset = ZoneOffset.UTC;
	
	protected LocalDateTime startTime;
	
	@BeforeEach
	protected void startUp(TestInfo info) {
		log.info("Executing {}", getTestName(info));
		startTime = LocalDateTime.now(zoneOffset);
	}
	
	@AfterEach
	protected void tearDown(TestInfo info) {
		final LocalDateTime endTime = LocalDateTime.now(zoneOffset);
		final float testDuration = Duration.between(startTime, endTime).toNanos() / 1000000.0F;
		log.info("Executed {} in {} seconds\n", getTestName(info), testDuration);
	}
	
	protected void setValue(Object target, String field, Object value, int parentLevel) throws Exception {
		Class<? extends Object> clazz = target.getClass();
		for(int i = 0; i < parentLevel; i++) {
			clazz = clazz.getSuperclass();
		}
		Field f = clazz.getDeclaredField(field);
		f.setAccessible(true);
		f.set(target, value);
		f.setAccessible(false);
	}

	protected void setValue(Object target, String field, Object value) throws Exception {
		setValue(target, field, value, 0);
	}
	
	protected String getTestName(TestInfo info) {
		return info.getDisplayName().substring(0, info.getDisplayName().length() - 2);
	}
}
