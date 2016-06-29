package com.choicemaker.xmlencryption;

import java.util.Map;

import org.w3c.dom.Element;

/**
 * An EncryptionScheme generates and recovers secret key information.
 */
public interface EncryptionScheme {

	/**
	 * Generally the id of an encryption policy should be the fully qualified
	 * class name that uniquely identifies a particular encryption scheme.
	 */
	String getSchemeId();

	/**
	 * Checks that an encryption credential contains enough information that it
	 * might be valid for encryption.
	 */
	boolean isConsistentWithEncryption(EncryptionCredential ec);

	/**
	 * Checks that an encryption credential contains enough information that it
	 * might be valid for decryption.
	 */
	boolean isConsistentWithDecryption(EncryptionCredential ec);

	SecretKeyInfoFactory getSecretKeyInfoFactory(EncryptionCredential ec,
			String algorithmName, Map<String, String> encryptionContext);

	SecretKeyInfo recoverSecretKeyInfo(Element encryptedKeyElement);

	String getDefaultAlgorithmName();

}
