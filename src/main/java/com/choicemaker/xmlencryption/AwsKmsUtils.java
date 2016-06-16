package com.choicemaker.xmlencryption;

import java.nio.ByteBuffer;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.services.kms.AWSKMSClient;
import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.services.kms.model.DecryptResult;
import com.amazonaws.services.kms.model.GenerateDataKeyRequest;
import com.amazonaws.services.kms.model.GenerateDataKeyResult;
import com.choicemaker.util.Precondition;
import com.choicemaker.util.StringUtils;

public class AwsKmsUtils {

	public static final String DEFAULT_AWS_KEY_ENCRYPTION_ALGORITHM = "AES_256";

	public static ByteBuffer computeSecretBytes(AWSCredentials creds,
			String masterKeyId, String algorithm, String encValueSecretKey,
			String endpoint) {
		Precondition.assertNonNullArgument("null credentials", creds);
		Precondition.assertNonEmptyString("null or blank master key id",
				masterKeyId);
		Precondition.assertNonEmptyString("null or blank encrypted value",
				encValueSecretKey);
		if (!StringUtils.nonEmptyString(algorithm)) {
			algorithm = DEFAULT_AWS_KEY_ENCRYPTION_ALGORITHM;
		}

		AWSKMSClient kms = new AWSKMSClient(creds);
		if (endpoint != null) {
			kms.setEndpoint(endpoint);
		}

		byte[] encBytes = encValueSecretKey.getBytes();
		ByteBuffer encryptedKey = ByteBuffer.wrap(encBytes);
		DecryptRequest request = new DecryptRequest()
				.withCiphertextBlob(encryptedKey);
		DecryptResult result = kms.decrypt(request);
		ByteBuffer retVal = result.getPlaintext();

		return retVal;
	}

	public static ByteBuffer createSessionKey(AWSCredentials creds,
			String masterKeyId, String algorithm, String endpoint) {

		GenerateDataKeyResult dataKeyResult = AwsKmsUtils.generateDataKey(
				creds, masterKeyId, algorithm, endpoint);

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
			algorithm = DEFAULT_AWS_KEY_ENCRYPTION_ALGORITHM;
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

	public static AWSCredentials getDefaultAWSCredentials() {
		DefaultAWSCredentialsProviderChain credsProvider = new DefaultAWSCredentialsProviderChain();
		AWSCredentials creds = credsProvider.getCredentials();
		return creds;
	}

	private AwsKmsUtils() {
	}
}
