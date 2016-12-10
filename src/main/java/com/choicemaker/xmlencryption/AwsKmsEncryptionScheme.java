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

import java.util.Map;

import org.w3c.dom.Element;

import com.amazonaws.auth.AWSCredentials;
import com.choicemaker.utilcopy01.Precondition;
import com.choicemaker.utilcopy01.StringUtils;

public class AwsKmsEncryptionScheme extends AbstractAwsKmsEncryptionScheme {

	public static final String DEFAULT_SCHEME_ID =
		AwsKmsEncryptionScheme.class.getName();

	public AwsKmsEncryptionScheme() {
		this(DefaultAlgorithms.DEFAULT_AWS_KEY_ENCRYPTION_ALGORITHM,
				DefaultAlgorithms.DEFAULT_DOC_ENCRYPT_ALGORITHM,
				DEFAULT_SCHEME_ID);
	}

	public AwsKmsEncryptionScheme(String keyAlgo, String docAlgo,
			String schemeId) {
		super(keyAlgo, docAlgo, schemeId);
	}

	@Override
	public boolean isConsistentWithEncryption(CredentialSet ec) {
		boolean retVal = ec != null;
		if (retVal) {
			for (String pn : AwsKmsProperties.getRequiredPropertyNames()) {
				String value = ec.get(pn);
				if (!StringUtils.nonEmptyString(value)) {
					retVal = false;
				}
			}
		}
		return retVal;
	}

	@Override
	public boolean isConsistentWithDecryption(CredentialSet ec) {
		return isConsistentWithEncryption(ec);
	}

	// @Override
	// public String getSchemeId() {
	// return AwsKmsEncryptionScheme.class.getName();
	// }

	@Override
	public SecretKeyInfoFactory getSecretKeyInfoFactory(CredentialSet ec,
			String algorithmName, Map<String, String> unused) {
		Precondition.assertNonNullArgument("null credential", ec);
		Precondition.assertBoolean(isConsistentWithEncryption(ec));
		Precondition.assertNonEmptyString("null or blank algorithm name",
				algorithmName);

		SecretKeyInfoFactory retVal =
			new AwsKmsSecretKeyInfoFactory(ec, algorithmName);
		return retVal;
	}

	@Override
	public SecretKeyInfo recoverSecretKeyInfo(Element encryptedKeyElement) {
		// TODO Auto-generated method stub
		throw new Error("not yet implemented");
	}

	// @Override
	// public String getKeyEncryptionAlgorithm() {
	// return DefaultAlgorithms.DEFAULT_AWS_KEY_ENCRYPTION_ALGORITHM;
	// }

	// @Override
	// public String getDocumentEncryptionAlgorithm() {
	// return DefaultAlgorithms.DEFAULT_DOC_ENCRYPT_ALGORITHM;
	// }

	public String getEndpoint(CredentialSet ec) {
		String retVal = AwsKmsProperties.getEndpoint(ec.getProperties());
		return retVal;
	}

	public AWSCredentials getAwsKmsCredentials(CredentialSet ec) {
		return AwsKmsCredentialSet.createAWSCredentials(ec.getProperties());
	}

	public String getMasterKeyId(CredentialSet ec) {
		String retVal = AwsKmsProperties.getMasterKeyId(ec.getProperties());
		return retVal;
	}

}
