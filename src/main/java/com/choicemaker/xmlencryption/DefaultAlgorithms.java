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

class DefaultAlgorithms {

	/**
	 * This value is passed to the AWS KMS service. It must be one of two
	 * enumerated values, AES_128 or AES_256.
	 *
	 * @see AwkKmsEncryptionScheme#
	 */
	public static final String DEFAULT_AWS_KEY_ENCRYPTION_ALGORITHM = "AES_256";

	/**
	 * This value appears as the value of the Algorithm attribute on the
	 * EncryptionMethod element within an EncryptedKey element. The value of
	 * this constant is not used for any computation. It is purely informative.
	 * Encryption and decryption work just as well if the value of this manifest
	 * constant is set to {@link #DEFAULT_AWS_KEY_ENCRYPTION_ALGORITHM}.
	 */
	public static final String DECLARED_KEY_ENCRYPTION = "http://www.w3.org/2001/04/xmlenc#kw-aes256";

	/**
	 * This value appears as the value of the Algorithm attribute of the
	 * EncryptionMethod element within the EncryptedData element. It is also
	 * used to look up an instance XMLCipher that is then used to encrypt an XML
	 * document.
	 */
	public static final String DEFAULT_DOC_ENCRYPT_ALGORITHM = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";

	private DefaultAlgorithms() {
	}

}
