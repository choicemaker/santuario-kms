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

import java.io.IOException;
import java.util.Properties;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.BasicAWSCredentials;
import com.choicemaker.utilcopy01.Precondition;
import com.choicemaker.utilcopy01.StringUtils;

public class AwsKmsCredentialSet extends CredentialSet {

	/**
	 * Creates an instance of AWSCredentials from
	 * {@link AwsKmsProperties#PN_ACCESSKEY access-} and
	 * {@link AwsKmsProperties#PN_SECRETKEY secret-}key properties defined by
	 * the specified set of properties.
	 * 
	 * @param a
	 *            non-null, non-blank set of properties
	 * @return a non-null instance of AWSCredentials
	 * @throws IllegalArgumentException
	 *             if {@link AwsKmsProperties#PN_ACCESSKEY access-} and
	 *             {@link AwsKmsProperties#PN_SECRETKEY secret-}key properties
	 *             are not defined in the specified set of properties.
	 */
	public static AWSCredentials createAWSCredentials(Properties p) {
		Precondition.assertNonNullArgument("null properties", p);
		String accessKey = AwsKmsProperties.getAccessKey(p);
		if (!StringUtils.nonEmptyString(accessKey)) {
			String msg =
				"Missing property '" + AwsKmsProperties.PN_ACCESSKEY + "'";
			throw new IllegalArgumentException(msg);
		}
		String secretKey = AwsKmsProperties.getSecretKey(p);
		if (!StringUtils.nonEmptyString(secretKey)) {
			String msg =
				"Missing property '" + AwsKmsProperties.PN_SECRETKEY + "'";
			throw new IllegalArgumentException(msg);
		}
		AWSCredentials retVal = new BasicAWSCredentials(accessKey, secretKey);
		return retVal;
	}

	/**
	 * Creates a credential set with the specified name from properties loaded
	 * by AwsKmsProperties.loadAwsKmsProperties(). Equivalent to
	 * 
	 * <pre>
	 * AwsKmsCredentialSet(name, AwsKmsProperties.loadAwsKmsProperties())
	 * </pre>
	 * 
	 * @param name
	 *            a non-null, non-blank String
	 * @throws IOException
	 *             if AwsKmsProperties.loadAwsKmsProperties() fails
	 */
	public AwsKmsCredentialSet(String name) throws IOException {
		this(name, AwsKmsProperties.loadAwsKmsProperties());
	}

	/**
	 * Creates a credential set from the specified properties.
	 * 
	 * @param name
	 *            a non-null, non-blank String
	 * @param p
	 *            a non-null set of properties that includes all required AWS
	 *            KMS properties.
	 * @throws IllegalArgumentException
	 *             if the specified properties are null or are missing required
	 *             AWS KMS properties.
	 * @see AwsKmsProperties.hasAwsParameters(Properties)
	 */
	public AwsKmsCredentialSet(String name, Properties p) {
		super(name);
		Precondition.assertBoolean("Missing required AWS KMS properties",
				AwsKmsProperties.hasAwsParameters(p));
		this.putAll(p);
	}

}
