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

public class AwsKmsEncryptionScheme extends AbstractAwsKmsEncryptionScheme {

	public static final String DEFAULT_SCHEME_ID =
		AwsKmsEncryptionScheme.class.getName();

	public AwsKmsEncryptionScheme() {
		this(DefaultAlgorithms.DEFAULT_AWS_KEY_ENCRYPTION_ALGORITHM,
				DefaultAlgorithms.DEFAULT_DOC_ENCRYPT_ALGO,
				DEFAULT_SCHEME_ID);
	}

	public AwsKmsEncryptionScheme(String keyAlgo, String docAlgo,
			String schemeId) {
		super(keyAlgo, docAlgo, schemeId);
	}

}
