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

import static com.choicemaker.xmlencryption.DefaultAlgorithms.DEFAULT_AWS_KEY_ENCRYPTION_ALGORITHM;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Properties;
import java.util.logging.Logger;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.services.kms.model.GenerateDataKeyResult;
import com.choicemaker.utilcopy01.DOMUtils;
import com.choicemaker.utilcopy01.Precondition;
import com.choicemaker.utilcopy01.WSS4JConstants;

public class AwsKmsSecretKeyInfoFactory implements SecretKeyInfoFactory {

	private static final Logger logger = Logger
			.getLogger(AwsKmsSecretKeyInfoFactory.class.getName());

	public static final String endpointFromARN(String arn) {
		String region = parseRegionfromKeyArn(arn);
		if (region == null) {
			throw new IllegalArgumentException("Not an ARN: '" + arn + "'");
		}
		String retVal = "https://kms." + region + ".amazonaws.com";
		return retVal;
	}

	/**
	 * From {@link KmsMasterKeyProvider.parseRegionfromKeyArn(String)}
	 *
	 * @param keyArn
	 * @return
	 */
	private static String parseRegionfromKeyArn(final String keyArn) {
		final String[] parts = keyArn.split(":", 5);

		if (!parts[0].equals("arn")) {
			// Not an arn
			return null;
		}
		// parts[1].equals("aws"); // This can vary
		if (!parts[2].equals("kms")) {
			// Not a kms arn
			return null;
		}
		return parts[3]; // return region
	}

	private final String endpoint;
	private final String masterKeyId;
	private final String algorithm;
	private final AWSCredentials creds;

	public AwsKmsSecretKeyInfoFactory() throws IOException {
		this(DEFAULT_AWS_KEY_ENCRYPTION_ALGORITHM);
	}

	public AwsKmsSecretKeyInfoFactory(String algorithm) throws IOException {
		this(AwsKmsProperties.loadAwsKmsProperties(), algorithm);
	}

	public AwsKmsSecretKeyInfoFactory(CredentialSet cs) {
		this(cs, DEFAULT_AWS_KEY_ENCRYPTION_ALGORITHM);
	}

	public AwsKmsSecretKeyInfoFactory(CredentialSet cs, String algorithm) {
		this(cs.getProperties(), algorithm);
	}

	public AwsKmsSecretKeyInfoFactory(Properties p) {
		this(p, DEFAULT_AWS_KEY_ENCRYPTION_ALGORITHM);
	}

	public AwsKmsSecretKeyInfoFactory(Properties p, String algorithm) {
		Precondition.assertNonEmptyString("null or blank algorithm", algorithm);
		Precondition.assertBoolean("invalid AWS KMS credentials",
				AwsKmsProperties.hasAwsParameters(p));

		this.masterKeyId = AwsKmsProperties.getMasterKeyId(p);
		this.endpoint = AwsKmsProperties.getEndpoint(p);
		this.creds = AwsKmsCredentialSet.createAWSCredentials(p);
		this.algorithm = algorithm;
	}

	@Override
	public SecretKeyInfo createSessionKey() {
		return createSessionKey(creds, masterKeyId, algorithm, endpoint);
	}

	public static SecretKeyInfo createSessionKey(AWSCredentials creds,
			String masterKeyId, String algorithm, String endpoint) {
		GenerateDataKeyResult dataKeyResult =
			AwsKmsUtils
					.generateDataKey(creds, masterKeyId, algorithm, endpoint);

		ByteBuffer plaintextKey = dataKeyResult.getPlaintext();
		final byte[] key = new byte[plaintextKey.remaining()];
		plaintextKey.get(key);

		ByteBuffer encryptedKey = dataKeyResult.getCiphertextBlob();
		final byte[] encKey = new byte[encryptedKey.remaining()];
		encryptedKey.get(encKey);

		Document doc = DOMUtils.newDocument();
		final Element keyInfoElement =
			doc.createElementNS(WSS4JConstants.SIG_NS,
					WSS4JConstants.SIG_PREFIX + ":" + WSS4JConstants.KEYINFO_LN);
		keyInfoElement.setAttributeNS(WSS4JConstants.XMLNS_NS, "xmlns:"
				+ WSS4JConstants.SIG_PREFIX, WSS4JConstants.SIG_NS);
		Element keyNameElement =
			doc.createElementNS(WSS4JConstants.SIG_NS,
					WSS4JConstants.SIG_PREFIX + ":KeyName");
		keyNameElement.setTextContent(masterKeyId);
		keyInfoElement.appendChild(keyNameElement);

		SecretKeyInfo retVal = new SecretKeyInfo(key, encKey, keyInfoElement);
		logger.fine(retVal.toString());

		return retVal;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		AwsKmsSecretKeyInfoFactory other = (AwsKmsSecretKeyInfoFactory) obj;
		if (algorithm == null) {
			if (other.algorithm != null)
				return false;
		} else if (!algorithm.equals(other.algorithm))
			return false;
		if (endpoint == null) {
			if (other.endpoint != null)
				return false;
		} else if (!endpoint.equals(other.endpoint))
			return false;
		if (masterKeyId == null) {
			if (other.masterKeyId != null)
				return false;
		} else if (!masterKeyId.equals(other.masterKeyId))
			return false;
		return true;
	}

	public String getAlgorithm() {
		return algorithm;
	}

	public String getEndpoint() {
		return endpoint;
	}

	public String getMasterKeyId() {
		return masterKeyId;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result =
			prime * result + ((algorithm == null) ? 0 : algorithm.hashCode());
		result =
			prime * result + ((endpoint == null) ? 0 : endpoint.hashCode());
		result =
			prime * result
					+ ((masterKeyId == null) ? 0 : masterKeyId.hashCode());
		return result;
	}

	@Override
	public String toString() {
		return "SecretKeyInfoFactory [masterKeyId=" + masterKeyId
				+ ", algorithm=" + algorithm + "]";
	}

}
