/*
 * Copyright (c) 2016 ChoiceMaker LLC and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License
 * v1.0 which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *     ChoiceMaker LLC - initial API and implementation
 */
package com.choicemaker.xmlencryption;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;

import org.junit.Test;

/**
 * These tests require AWS KMS properties to be defined externally. The master
 * key must be specified as an Amazon Resource Number (ARN).
 * 
 * @see AwsKmsProperties#loadAwsKmsProperties()
 *
 * @author rphall
 */
public class SecretKeyInfoFactoryTest {

	public static final String FAKE_MASTER_KEY_ARN =
		"arn:aws:kms:us-east-1:012345678901:key/a1234567-800b-1234-5a67-8a90b123456c";
	public static final String AWS_ENDPOINT =
		"https://kms.us-east-1.amazonaws.com";

	@Test
	public void testCreateSessionKey() throws IOException {
		final SecretKeyInfoFactory skif = new AwsKmsSecretKeyInfoFactory();
		final SecretKeyInfo ski = skif.createSessionKey();
		assertTrue(ski != null);
		assertTrue(ski.getKey() != null);
		assertTrue(ski.getEncryptedSecret() != null);
		assertTrue(ski.getKeyInfoReference() != null);

		final SecretKeyInfo ski2 = skif.createSessionKey();
		assertTrue(!ski.getKey().equals(ski2.getKey()));
		assertTrue(!ski.getEncryptedSecret().equals(ski2.getEncryptedSecret()));
		assertTrue(!ski.getKeyInfoReference()
				.equals(ski2.getKeyInfoReference()));
	}

	@Test
	public void testEndpointFromARN() {
		String computed =
			AwsKmsSecretKeyInfoFactory.endpointFromARN(FAKE_MASTER_KEY_ARN);
		String expected = AWS_ENDPOINT;
		assertTrue(computed != null);
		assertTrue(computed.equals(expected));
	}

	@Test
	public void testSecretKeyInfoFactoryString() {
		AwsKmsSecretKeyInfoFactory skif = null;
		try {
			skif = new AwsKmsSecretKeyInfoFactory();
		} catch (Throwable t) {
			fail(t.toString());
		}
		assertTrue(DefaultAlgorithms.DEFAULT_AWS_KEY_ENCRYPTION_ALGORITHM
				.equals(skif.getAlgorithm()));
	}

}
