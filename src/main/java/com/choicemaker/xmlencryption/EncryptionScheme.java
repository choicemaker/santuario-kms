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

/**
 * An EncryptionScheme generates and recovers secret key information.
 */
public interface EncryptionScheme {

	/**
	 * Generally the id of an encryption scheme should be a name that uniquely
	 * identifies a particular encryption scheme.
	 */
	String getSchemeId();

	/**
	 * Checks that a credential set contains enough information that it might be
	 * valid for encryption.
	 */
	boolean isConsistentWithEncryption(CredentialSet ec);

	/**
	 * Checks that a credential set contains enough information that it might be
	 * valid for decryption.
	 */
	boolean isConsistentWithDecryption(CredentialSet ec);

	SecretKeyInfoFactory getSecretKeyInfoFactory(CredentialSet ec,
			String algorithmName, Map<String, String> encryptionContext);

	SecretKeyInfo recoverSecretKeyInfo(Element encryptedKeyElement);

	/** Returns the name of the algorithm used to encrypt a data key */
	String getKeyEncryptionAlgorithm();

	/** Returns the name of the algorithm used to encrypt an XML document */
	String getDocumentEncryptionAlgorithm();

	/**
	 * Instances should be equal if they have the same scheme id.
	 */
	@Override
	boolean equals(Object o);

	/**
	 * Hash codes should computed from the scheme id.
	 */
	@Override
	int hashCode();

	/**
	 * toString() should return the scheme id
	 */
	@Override
	String toString();

}
