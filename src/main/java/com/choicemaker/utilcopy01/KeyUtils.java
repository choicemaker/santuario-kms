/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package com.choicemaker.utilcopy01;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.xml.security.algorithms.JCEMapper;

/**
 * Copied from wss4j-ws-security-common-2.1.5-sources.jar, and then repackaged
 * and pruned, to reduce dependencies of the santuario-kms library. For internal
 * use only.
 */
public final class KeyUtils {
	private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory
			.getLogger(KeyUtils.class);
	private static final int MAX_SYMMETRIC_KEY_SIZE = 1024;

	private KeyUtils() {
		// complete
	}

	/**
	 * Returns the length of the key in # of bytes
	 *
	 * @param algorithm
	 *            the URI of the algorithm. See
	 *            http://www.w3.org/TR/xmlenc-core1/
	 * @return the key length
	 */
	public static int getKeyLength(String algorithm) {
		return JCEMapper.getKeyLengthFromURI(algorithm) / 8;
	}

	/**
	 * Convert the raw key bytes into a SecretKey object of type algorithm.
	 */
	public static SecretKey prepareSecretKey(String algorithm, byte[] rawKey) {
		// Do an additional check on the keysize required by the encryption
		// algorithm
		int size = 0;
		try {
			size = getKeyLength(algorithm);
		} catch (Exception e) {
			// ignore - some unknown (to JCEMapper) encryption algorithm
			if (LOG.isDebugEnabled()) {
				LOG.debug(e.getMessage());
			}
		}
		String keyAlgorithm = JCEMapper.getJCEKeyAlgorithmFromURI(algorithm);
		SecretKeySpec keySpec;
		if (size > 0 && !algorithm.endsWith("gcm")
				&& !algorithm.contains("hmac-")) {
			keySpec =
				new SecretKeySpec(rawKey, 0, rawKey.length > size ? size
						: rawKey.length, keyAlgorithm);
		} else if (rawKey.length > MAX_SYMMETRIC_KEY_SIZE) {
			// Prevent a possible attack where a huge secret key is specified
			keySpec =
				new SecretKeySpec(rawKey, 0, MAX_SYMMETRIC_KEY_SIZE,
						keyAlgorithm);
		} else {
			keySpec = new SecretKeySpec(rawKey, keyAlgorithm);
		}
		return keySpec;
	}

}
