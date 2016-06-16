package com.choicemaker.xmlencryption;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

/**
 * These tests require default AWS credentials provider with permission to use
 * the default master key specified below. See
 * "Providing AWS Credentials in the AWS SDK for Java"
 * (http://links.rph.cx/24kqE58)
 * 
 * @author rphall
 */
public class SecretKeyInfoFactoryTest {

	public static final String MASTER_KEY_ARN = "arn:aws:kms:us-east-1:073204089135:key/b4985799-964b-4383-8b91-9d82d866858d";
	public static final String AWS_ENDPOINT = "https://kms.us-east-1.amazonaws.com";

	@Test
	public void testEndpointFromARN() {
		String computed = SecretKeyInfoFactory.endpointFromARN(MASTER_KEY_ARN);
		String expected = AWS_ENDPOINT;
		assertTrue(computed != null);
		assertTrue(computed.equals(expected));
	}

	@Test
	public void testSecretKeyInfoFactoryString() {
		SecretKeyInfoFactory skif = null;
		try {
			skif = new SecretKeyInfoFactory(MASTER_KEY_ARN);
		} catch (Throwable t) {
			fail(t.toString());
		}
		assertTrue(MASTER_KEY_ARN.equals(skif.getMasterKeyId()));
		assertTrue(AwsKmsUtils.DEFAULT_AWS_KEY_ENCRYPTION_ALGORITHM.equals(skif
				.getAlgorithm()));
		assertTrue(null == skif.getEndpoint());
	}

	@Test
	public void testSecretKeyInfoFactoryStringStringString() {
		final String algorithm = "fakeAlgorithm";
		final String endpoint = "fakeEndpoint";
		SecretKeyInfoFactory skif = null;
		try {
			skif = new SecretKeyInfoFactory(MASTER_KEY_ARN, algorithm, endpoint);
		} catch (Throwable t) {
			fail(t.toString());
		}
		assertTrue(MASTER_KEY_ARN.equals(skif.getMasterKeyId()));
		assertTrue(algorithm.equals(skif.getAlgorithm()));
		assertTrue(endpoint.equals(skif.getEndpoint()));
	}

	@Test
	public void testCreateSessionKey() {
		final SecretKeyInfoFactory skif = new SecretKeyInfoFactory(
				MASTER_KEY_ARN);
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
	public void testCreateSessionKeyStringStringString() {
		final SecretKeyInfoFactory skif = new SecretKeyInfoFactory(
				MASTER_KEY_ARN, AwsKmsUtils.DEFAULT_AWS_KEY_ENCRYPTION_ALGORITHM,
				SecretKeyInfoFactory.endpointFromARN(MASTER_KEY_ARN));
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

}
