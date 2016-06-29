package com.choicemaker.xmlencryption;

import java.util.Map;

import org.w3c.dom.Element;

/**
 * An EncryptionScheme generates and recovers secret key information.
 */
public interface EncryptionScheme {

	/**
	 * Generally the id of an encryption scheme should be the fully qualified
	 * class name that uniquely identifies a particular encryption scheme.
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

}
