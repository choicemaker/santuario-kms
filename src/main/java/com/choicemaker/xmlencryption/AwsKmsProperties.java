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

import static com.choicemaker.utilcopy01.SystemPropertyUtils.PV_FILE_SEPARATOR;
import static com.choicemaker.utilcopy01.SystemPropertyUtils.PV_USER_HOME;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import com.choicemaker.utilcopy01.Precondition;
import com.choicemaker.utilcopy01.StringUtils;

/**
 * Required and optional properties that are used to access a master key managed
 * by the AWS KMS service.
 * <p/>
 * These properties may loaded from a file. By default, the property file is
 * assumed to be in a file named {@link #DEFAULT_PROPERTY_FILENAME
 * santuario-kms.properties} located in a directory named
 * {@link #DEFAULT_PROPERTY_DIRNAME .aws} within the user's home directory.
 * <p/>
 * Alternatively, AWK KMS properties may be loaded from an arbitrary by
 * specifying a value for a System property named {@link #PN_AWS_KMS_PROPERTIES
 * awsKmsProperties}. If a properties can not be found at the default location
 * or a location specified by {@link #PN_AWS_KMS_PROPERTIES awsKmsProperties},
 * then property loading will fail with an {@link IllegalStateException}.
 * <p/>
 * Property values may be encrypted. If property values are encrypted, encrypted
 * values are enclosed by encryption {@link #PN_ENC_START_MARKER start} and
 * {@link #PN_ENC_END_MARKER end} markers.
 * <p/>
 * The password for decrypting property values is specified by a System property
 * named {@link #PN_AWS_KMS_PROPERTIES_PASSWORD awsKmsPropertiesPassword}. If no
 * System property is set, then property values are assumed to be unencrypted
 * clear-text and are used exactly as specified (including any encryption
 * {@link #PN_ENC_START_MARKER start} and {@link #PN_ENC_END_MARKER end}
 * markers).
 */
public class AwsKmsProperties {

	/** Required AWS KMS credential -- the user of a master key */
	public static final String PN_ACCESSKEY = "aws.user.accessKey";

	/** Required AWS KMS credential -- the user 'password' */
	public static final String PN_SECRETKEY = "aws.user.secretKey";

	/** Required AWS KMS parameter -- the master key used to create session keys */
	public static final String PN_MASTERKEY = "aws.kms.masterKey";

	/**
	 * A text prefix that marks the start of a password encrypted value.
	 */
	public static final String PN_ENC_START_MARKER = "ENC(";

	/**
	 * A text suffix that marks the end of a password encrypted value.
	 */
	public static final String PN_ENC_END_MARKER = ")";

	/**
	 * Optional AWS KMS parameter -- a region-specific URL for the AWS KMS
	 * service intended to reduce service latency.
	 */
	public static final String PN_ENDPOINT = "aws.endpoint";

	/**
	 * The default name of a file defining AWS KMS property values.
	 */
	public static final String DEFAULT_PROPERTY_FILENAME =
		"santuario-kms.properties";

	/**
	 * The default folder, within a user's home directory, where the default
	 * property file is expected to be located.
	 */
	public static final String DEFAULT_PROPERTY_DIRNAME = ".aws";

	/**
	 * The absolute path of the default file defining AWS KMS property values.
	 */
	public static final String DEFAULT_PROPERTY_PATH = PV_USER_HOME
			+ PV_FILE_SEPARATOR + DEFAULT_PROPERTY_DIRNAME + PV_FILE_SEPARATOR
			+ DEFAULT_PROPERTY_FILENAME;

	/**
	 * The name of an optional System property that specifies the name of a file
	 * that defines AWS KMS properties.
	 */
	public static final String PN_AWS_KMS_PROPERTIES = "awsKmsProperties";

	/**
	 * The name of an optional System property that specifies the password used
	 * to encrypt sensitive AWS KMS property values.
	 */
	public static final String PN_AWS_KMS_PROPERTIES_PASSWORD =
		"awsKmsPropertiesPassword";

	private static final String[] REQUIRED_PROPERTY_NAMES = new String[] {
			PN_ACCESSKEY, PN_SECRETKEY, PN_MASTERKEY };

	private static final AtomicReference<Set<String>> REQUIRED_PROPERTY_NAME_SET =
		new AtomicReference<>(null);

	/**
	 * Returns the set of property names that must be defined by a valid
	 * AwsKmsCredentialSet.
	 * 
	 * @return a set consisting of {@link #PN_ACCESSKEY}, {@link #PN_SECRETKEY}
	 *         and {@link #PN_MASTERKEY}
	 */
	public static Set<String> getRequiredPropertyNames() {
		Set<String> retVal = REQUIRED_PROPERTY_NAME_SET.get();
		if (retVal == null) {
			Set<String> update = new HashSet<>();
			update.addAll(Arrays.asList(REQUIRED_PROPERTY_NAMES));
			retVal = Collections.unmodifiableSet(update);
			if (!REQUIRED_PROPERTY_NAME_SET.compareAndSet(null, retVal)) {
				retVal = REQUIRED_PROPERTY_NAME_SET.get();
			}
			assert retVal.equals(update);
		}
		assert retVal != null;
		return retVal;
	}

	/**
	 * Checks if a set of properties defines values for the required AWS KMS
	 * parameters.
	 * 
	 * @param p
	 *            set of properties, possibly null
	 * @return true if non-null, non-blank values are defined for
	 *         {@link #PN_ACCESSKEY}, {@link #PN_SECRETKEY} and
	 *         {@link #PN_MASTERKEY}
	 */
	public static boolean hasAwsParameters(Properties p) {
		boolean retVal = false;
		if (p != null) {
			retVal = true;
			for (String pn : getRequiredPropertyNames()) {
				String value = p.getProperty(pn);
				if (!StringUtils.nonEmptyString(value)) {
					retVal = false;
					break;
				}
			}
		}
		return retVal;
	}

	/**
	 * @param p
	 *            set of properties, possibly null, possibly defining a value
	 *            for {@link #PN_ACCESSKEY}
	 * @return the user of a master key, possibly null
	 */
	public static String getAccessKey(Properties p) {
		return p == null ? null : p.getProperty(AwsKmsProperties.PN_ACCESSKEY);
	}

	/**
	 * @param p
	 *            set of properties, possibly null, possibly defining a value
	 *            for {@link #PN_SECRETKEY}
	 * @return the user 'password', possibly null
	 */
	public static String getSecretKey(Properties p) {
		return p == null ? null : p.getProperty(AwsKmsProperties.PN_SECRETKEY);
	}

	/**
	 * @param p
	 *            set of properties, possibly null, possibly defining a value
	 *            for {@link #PN_MASTERKEY}
	 * @return the master key, possibly null, used to create session keys
	 */
	public static String getMasterKeyId(Properties p) {
		return p == null ? null : p.getProperty(AwsKmsProperties.PN_MASTERKEY);
	}

	/**
	 * @param p
	 *            set of properties, possibly null, possibly defining a value
	 *            for {@link #PN_ENDPOINT}
	 * @return a region-specific URL for the AWS KMS service, possibly null
	 */
	public static String getEndpoint(Properties p) {
		return p == null ? null : p.getProperty(AwsKmsProperties.PN_ENDPOINT);
	}

	/**
	 * Load the properties defined by a file specified by the System property
	 * {@link #PN_AWS_KMS_PROPERTIES}, or if this property is not set, by the
	 * file at the default location {@link #DEFAULT_PROPERTY_PATH}. Equivalent
	 * to
	 * 
	 * <pre>
	 * String path = System.getProperty(PN_AWS_KMS_PROPERTIES, DEFAULT_PROPERTY_PATH);
	 * loadAwsKmsProperties(path);
	 * </pre>
	 * 
	 * @return a non-null Properties file
	 * @throws FileNotFound
	 *             if the specified file does not exist
	 * @throws IOException
	 *             if properties can not loaded from the specified file.
	 */
	public static Properties loadAwsKmsProperties() throws IOException {
		String path =
			System.getProperty(PN_AWS_KMS_PROPERTIES, DEFAULT_PROPERTY_PATH);
		return loadAwsKmsProperties(path);
	}

	/**
	 * Load the properties defined by a file specified by the System property
	 * {@link #PN_AWS_KMS_PROPERTIES}, or if this property is not set, by the
	 * file at the default location {@link #DEFAULT_PROPERTY_PATH}. If no file
	 * exits at the specified path, a FileNotFound exception is thrown. If
	 * properties can not be loaded from the specified file, an IOException is
	 * thrown.
	 * 
	 * @param path
	 *            a non-null, non-blank path to a properties file.
	 * @return a non-null Properties file
	 * @throws FileNotFound
	 *             if the specified file does not exist
	 * @throws IOException
	 *             if properties can not loaded from the specified file.
	 */
	public static Properties loadAwsKmsProperties(String path)
			throws IOException {
		Precondition.assertNonEmptyString("null or blank file path", path);
		File f = new File(path);
		if (!f.exists()) {
			throw new FileNotFoundException("File does not exist: '" + path
					+ "'");
		}
		Properties p = new Properties();
		FileReader fr = new FileReader(f);
		p.load(fr);
		return p;
	}

	// public static ByteBuffer computeSecretBytes(AWSCredentials creds,
	// String masterKeyId, String algorithm, String encValueSecretKey,
	// String endpoint) throws Base64DecodingException {
	// Precondition.assertNonNullArgument("null credentials", creds);
	// Precondition.assertNonEmptyString("null or blank master key id",
	// masterKeyId);
	// Precondition.assertNonEmptyString("null or blank encrypted value",
	// encValueSecretKey);
	// if (!StringUtils.nonEmptyString(algorithm)) {
	// algorithm = DefaultAlgorithms.DEFAULT_AWS_KEY_ENCRYPTION_ALGORITHM;
	// }
	//
	// AWSKMSClient kms = new AWSKMSClient(creds);
	// if (endpoint != null) {
	// kms.setEndpoint(endpoint);
	// }
	//
	// byte[] encBase64 = encValueSecretKey.getBytes();
	// byte[] encBytes = Base64.decode(encBase64);
	// ByteBuffer encryptedKey = ByteBuffer.wrap(encBytes);
	// DecryptRequest request =
	// new DecryptRequest().withCiphertextBlob(encryptedKey);
	// DecryptResult result = kms.decrypt(request);
	// ByteBuffer retVal = result.getPlaintext();
	//
	// return retVal;
	// }
	//
	// public static ByteBuffer createSessionKey(AWSCredentials creds,
	// String masterKeyId, String algorithm, String endpoint) {
	//
	// GenerateDataKeyResult dataKeyResult =
	// AwsKmsProperties.generateDataKey(creds, masterKeyId, algorithm,
	// endpoint);
	//
	// ByteBuffer plaintextKey = dataKeyResult.getPlaintext();
	// final byte[] key = new byte[plaintextKey.remaining()];
	// plaintextKey.get(key);
	//
	// ByteBuffer retVal = dataKeyResult.getCiphertextBlob();
	// final byte[] encKey = new byte[retVal.remaining()];
	// retVal.get(encKey);
	//
	// return retVal;
	// }
	//
	// static GenerateDataKeyResult generateDataKey(AWSCredentials creds,
	// String masterKeyId, String algorithm, String endpoint) {
	// Precondition.assertNonNullArgument("null credentials", creds);
	// Precondition.assertNonEmptyString("null or blank master key id",
	// masterKeyId);
	// if (!StringUtils.nonEmptyString(algorithm)) {
	// algorithm = DefaultAlgorithms.DEFAULT_AWS_KEY_ENCRYPTION_ALGORITHM;
	// }
	//
	// AWSKMSClient kms = new AWSKMSClient(creds);
	// if (endpoint != null) {
	// kms.setEndpoint(endpoint);
	// }
	//
	// GenerateDataKeyRequest dataKeyRequest = new GenerateDataKeyRequest();
	// dataKeyRequest.setKeyId(masterKeyId);
	// dataKeyRequest.setKeySpec(algorithm);
	//
	// GenerateDataKeyResult retVal = kms.generateDataKey(dataKeyRequest);
	// return retVal;
	// }
	//
	// public static AWSCredentials getDefaultAWSCredentials() {
	// DefaultAWSCredentialsProviderChain credsProvider =
	// new DefaultAWSCredentialsProviderChain();
	// AWSCredentials creds = credsProvider.getCredentials();
	// return creds;
	// }
	//
	// private AwsKmsProperties() {
	// }
	//
	// /**
	// * @param p
	// * set of properties, possibly null, possibly defining a value
	// * for {@link #PN_ACCESSKEY}
	// * @return the user of a master key, possibly null
	// */
	// public static String getAccessKey(Properties p) {
	// return p == null ? null : p.getProperty(AwsKmsProperties.PN_ACCESSKEY);
	// }
	//
	// /**
	// * @param p
	// * set of properties, possibly null, possibly defining a value
	// * for {@link #PN_SECRETKEY}
	// * @return the user 'password', possibly null
	// */
	// public static String getSecretKey(Properties p) {
	// return p == null ? null : p.getProperty(AwsKmsProperties.PN_SECRETKEY);
	// }
	//
	// /**
	// * @param p
	// * set of properties, possibly null, possibly defining a value
	// * for {@link #PN_MASTERKEY}
	// * @return the master key, possibly null, used to create session keys
	// */
	// public static String getMasterKeyId(Properties p) {
	// return p == null ? null : p.getProperty(AwsKmsProperties.PN_MASTERKEY);
	// }
	//
	// /**
	// * @param p
	// * set of properties, possibly null, possibly defining a value
	// * for {@link #PN_ENDPOINT}
	// * @return a region-specific URL for the AWS KMS service, possibly null
	// */
	// public static String getEndpoint(Properties p) {
	// return p == null ? null : p.getProperty(AwsKmsProperties.PN_ENDPOINT);
	// }
	//
	// /**
	// * Checks if a set of properties defines values for the required AWS KMS
	// * parameters.
	// *
	// * @param p
	// * set of properties, possibly null
	// * @return true if non-null, non-blank values are defined for
	// * {@link #PN_ACCESSKEY}, {@link #PN_SECRETKEY} and
	// * {@link #PN_MASTERKEY}
	// */
	// public static boolean hasAwsParameters(Properties p) {
	// boolean retVal = false;
	// if (p != null) {
	// retVal =
	// StringUtils.nonEmptyString(getSecretKey(p))
	// && StringUtils.nonEmptyString(getSecretKey(p))
	// && StringUtils.nonEmptyString(getMasterKeyId(p));
	// }
	// return retVal;
	// }
	//
	// public static AWSCredentials getDefaultAWSCredentials() {
	// DefaultAWSCredentialsProviderChain credsProvider =
	// new DefaultAWSCredentialsProviderChain();
	// AWSCredentials creds = credsProvider.getCredentials();
	// return creds;
	// }
}
