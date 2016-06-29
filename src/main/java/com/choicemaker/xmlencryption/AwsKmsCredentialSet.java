package com.choicemaker.xmlencryption;

import com.amazonaws.auth.AWSCredentials;
import com.choicemaker.utilcopy01.Precondition;

public class AwsKmsCredentialSet extends CredentialSet {

	public AwsKmsCredentialSet(String name, String masterKeyId, String endpoint) {
		this(AwsKmsUtils.getDefaultAWSCredentials(), name, masterKeyId,
				endpoint);
	}

	public AwsKmsCredentialSet(AWSCredentials aws, String name,
			String masterKeyId, String endpoint) {
		super(name);
		Precondition.assertNonNullArgument("null AWS credentials", aws);
		Precondition.assertNonEmptyString("null or blank masterKeyId",
				masterKeyId);
		if (endpoint != null) {
			endpoint = endpoint.trim();
			if (endpoint.isEmpty()) {
				endpoint = null;
			}
		}

		String secretKeyId = aws.getAWSSecretKey();
		this.put(AwsKmsEncryptionScheme.PN_SECRETKEY, secretKeyId);
		String accessKeyId = aws.getAWSAccessKeyId();
		this.put(AwsKmsEncryptionScheme.PN_ACCESSKEY, accessKeyId);
		this.put(AwsKmsEncryptionScheme.PN_MASTERKEY, masterKeyId);
		if (endpoint != null) {
			this.put(AwsKmsEncryptionScheme.PN_ENDPOINT, endpoint);
		}
	}

}
