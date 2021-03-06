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

import java.nio.ByteBuffer;

import org.apache.xml.security.exceptions.Base64DecodingException;
import org.apache.xml.security.utils.Base64;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.services.kms.AWSKMSClient;
import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.services.kms.model.DecryptResult;
import com.amazonaws.services.kms.model.GenerateDataKeyRequest;
import com.amazonaws.services.kms.model.GenerateDataKeyResult;
import com.choicemaker.utilcopy01.Precondition;
import com.choicemaker.utilcopy01.StringUtils;

public class AwsKmsUtils {

	public static ByteBuffer computeSecretBytes(AWSCredentials creds,
			String masterKeyId, String algorithm, String encValueSecretKey,
			String endpoint) throws Base64DecodingException {
		Precondition.assertNonNullArgument("null credentials", creds);
		Precondition.assertNonEmptyString("null or blank master key id",
				masterKeyId);
		Precondition.assertNonEmptyString("null or blank encrypted value",
				encValueSecretKey);
		if (!StringUtils.nonEmptyString(algorithm)) {
			algorithm = DefaultAlgorithms.DEFAULT_AWS_KEY_ENCRYPTION_ALGORITHM;
		}

		AWSKMSClient kms = new AWSKMSClient(creds);
		if (endpoint != null) {
			kms.setEndpoint(endpoint);
		}

		byte[] encBase64 = encValueSecretKey.getBytes();
		byte[] encBytes = Base64.decode(encBase64);
		ByteBuffer encryptedKey = ByteBuffer.wrap(encBytes);
		DecryptRequest request =
			new DecryptRequest().withCiphertextBlob(encryptedKey);
		DecryptResult result = kms.decrypt(request);
		ByteBuffer retVal = result.getPlaintext();

		return retVal;
	}

	public static ByteBuffer createSessionKey(AWSCredentials creds,
			String masterKeyId, String algorithm, String endpoint) {

		GenerateDataKeyResult dataKeyResult =
			AwsKmsUtils
					.generateDataKey(creds, masterKeyId, algorithm, endpoint);

		ByteBuffer plaintextKey = dataKeyResult.getPlaintext();
		final byte[] key = new byte[plaintextKey.remaining()];
		plaintextKey.get(key);

		ByteBuffer retVal = dataKeyResult.getCiphertextBlob();
		final byte[] encKey = new byte[retVal.remaining()];
		retVal.get(encKey);

		return retVal;
	}

	static GenerateDataKeyResult generateDataKey(AWSCredentials creds,
			String masterKeyId, String algorithm, String endpoint) {
		Precondition.assertNonNullArgument("null credentials", creds);
		Precondition.assertNonEmptyString("null or blank master key id",
				masterKeyId);
		if (!StringUtils.nonEmptyString(algorithm)) {
			algorithm = DefaultAlgorithms.DEFAULT_AWS_KEY_ENCRYPTION_ALGORITHM;
		}

		AWSKMSClient kms = new AWSKMSClient(creds);
		if (endpoint != null) {
			kms.setEndpoint(endpoint);
		}

		GenerateDataKeyRequest dataKeyRequest = new GenerateDataKeyRequest();
		dataKeyRequest.setKeyId(masterKeyId);
		dataKeyRequest.setKeySpec(algorithm);

		GenerateDataKeyResult retVal = kms.generateDataKey(dataKeyRequest);
		return retVal;
	}

	private AwsKmsUtils() {
	}
}
