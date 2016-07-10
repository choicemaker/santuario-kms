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
import java.util.Properties;

import org.w3c.dom.Element;

import com.amazonaws.auth.AWSCredentials;
import com.choicemaker.utilcopy01.Precondition;
import com.choicemaker.utilcopy01.StringUtils;

/**
 * Implements all methods of the EncryptionSchema interface except
 * {@link EncryptionSchema#getSchemeId() getSchemeId()};
 */
public abstract class AbstractAwsKmsEncryptionScheme implements
		EncryptionScheme {

	public static SecretKeyInfo createSessionKey(AWSCredentials creds,
			String masterKeyId, String algorithm, String endpoint) {
		return AwsKmsSecretKeyInfoFactory.createSessionKey(creds, masterKeyId,
				algorithm, endpoint);
	}

	public static CredentialSet createCredentialSet(String name, Properties p) {
		AwsKmsCredentialSet retVal = new AwsKmsCredentialSet(name, p);
		return retVal;
	}

	private final String keyAlgo;
	private final String docAlgo;
	private final String schemeId;

	protected AbstractAwsKmsEncryptionScheme(String keyAlgo, String docAlgo,
			String schemeId) {
		Precondition.assertNonEmptyString(
				"null or blank key encryption algorithm", keyAlgo);
		Precondition.assertNonEmptyString(
				"null or blank document encryption algorithm", docAlgo);
		Precondition.assertNonEmptyString("null or blank scheme id", schemeId);
		this.keyAlgo = keyAlgo;
		this.docAlgo = docAlgo;
		this.schemeId = schemeId;
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

	@Override
	public String getSchemeId() {
		return schemeId;
	}

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

	@Override
	public String getKeyEncryptionAlgorithm() {
		return keyAlgo;
	}

	@Override
	public String getDocumentEncryptionAlgorithm() {
		return docAlgo;
	}

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
