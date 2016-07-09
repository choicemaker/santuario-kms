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

import java.util.Properties;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.BasicAWSCredentials;
import com.choicemaker.utilcopy01.Precondition;
import com.choicemaker.utilcopy01.StringUtils;

public class AwsKmsCredentialSet extends CredentialSet {

	/**
	 * Creates an instance of AWSCredentials from
	 * {@link AwsKmsProperties#PN_ACCESSKEY access-} and
	 * {@link AwsKmsProperties#PN_SECRETKEY secret-}key properties defined
	 * by the specified set of properties.
	 * @param a non-null, non-blank set of properties
	 * @return a non-null instance of AWSCredentials
	 * @throws IllegalArgumentException if {@link AwsKmsProperties#PN_ACCESSKEY access-} and
	 * {@link AwsKmsProperties#PN_SECRETKEY secret-}key properties are not defined
	 * in the specified set of properties.
	 */
	public static AWSCredentials createAWSCredentials(Properties p) {
		Precondition.assertNonNullArgument("null properties", p);
		String accessKey = AwsKmsProperties.getAccessKey(p);
		if (!StringUtils.nonEmptyString(accessKey)) {
			String msg = "Missing property '" + AwsKmsProperties.PN_ACCESSKEY + "'";
			throw new IllegalArgumentException(msg);
		}
		String secretKey = AwsKmsProperties.getSecretKey(p);
		if (!StringUtils.nonEmptyString(secretKey)) {
			String msg = "Missing property '" + AwsKmsProperties.PN_SECRETKEY + "'";
			throw new IllegalArgumentException(msg);
		}
		AWSCredentials retVal = new BasicAWSCredentials(accessKey, secretKey);
		return retVal;
	}

	/**
	 * Creates an invalid credential set with the specified name. To convert
	 * this into a valid credential set, add the
	 * {@link AwsKmsEncryptionScheme#getRequiredPropertyNames() property values
	 * required by the the AwsKmsEncryptionScheme}.
	 * 
	 * @param name
	 *            a non-null, non-blank String
	 */
	public AwsKmsCredentialSet(String name) {
		super(name);
	}

	/**
	 * Creates a valid credential set from the specified properties.
	 * 
	 * @param name
	 * @param
	 * @param masterKeyId
	 * @param endpoint
	 */
	public AwsKmsCredentialSet(String name, String masterKeyId, String endpoint) {
		this(AwsKmsProperties.getDefaultAWSCredentials(), name, masterKeyId,
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
