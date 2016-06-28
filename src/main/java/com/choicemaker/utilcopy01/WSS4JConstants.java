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

/**
 * Copied from wss4j-ws-security-common-2.1.5-sources.jar to reduce dependencies
 * of the santuario-kms library.
 */
public class WSS4JConstants {

	protected WSS4JConstants() {
		// complete
	}

	public static final String SIG_NS = "http://www.w3.org/2000/09/xmldsig#";
	public static final String ENC_NS = "http://www.w3.org/2001/04/xmlenc#";
	public static final String XMLNS_NS = "http://www.w3.org/2000/xmlns/";
	public static final String AES_256 = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";

	// Local names

	public static final String ENC_KEY_LN = "EncryptedKey";
	public static final String KEYINFO_LN = "KeyInfo";
	public static final String SIG_PREFIX = "ds";
	public static final String ENC_PREFIX = "xenc";
}