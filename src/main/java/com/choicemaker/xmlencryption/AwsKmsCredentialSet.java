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

import com.amazonaws.auth.AWSCredentials;
import com.choicemaker.utilcopy01.Precondition;

public class AwsKmsCredentialSet extends CredentialSet {

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
