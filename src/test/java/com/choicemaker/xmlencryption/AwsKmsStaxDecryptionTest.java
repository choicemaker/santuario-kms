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
package com.choicemaker.xmlencryption;

import static com.choicemaker.xmlencryption.AwsKmsStaxEncryptionTest.encryptEntireDocUsingStAX;
import static com.choicemaker.xmlencryption.AwsKmsStaxEncryptionTest.prepareWrappedEncryptionProperties;
import static com.choicemaker.xmlencryption.AwsKmsStaxEncryptionTest.printXMLBytes;
import static com.choicemaker.xmlencryption.TestUtils.checkNodeCount;
import static com.choicemaker.xmlencryption.TestUtils.getCredentialSet;
import static com.choicemaker.xmlencryption.TestUtils.getEncryptionScheme;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.crypto.SecretKey;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.InboundXMLSec;
import org.apache.xml.security.stax.ext.XMLSec;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.stax.impl.processor.output.XMLEncryptOutputProcessor;
import org.junit.Assert;

import com.choicemaker.utilcopy01.KeyUtils;

/**
 * Encrypts an entire document via StAX, but encryption fails for some documents
 * because the document root is left as plain text
 */
public class AwsKmsStaxDecryptionTest extends org.junit.Assert {

	static {
		org.apache.xml.security.Init.init();
	}

	private static final ClassLoader CLASS_LOADER =
		AwsKmsStaxEncryptionTest.class.getClassLoader();

	static final String docEncAlgo = DefaultAlgorithms.DEFAULT_DOC_ENCRYPT_ALGO;
	static final String keyEncAlgo = DefaultAlgorithms.DECLARED_KEY_ENCRYPTION;
	static final String encoding = "UTF-8";
	
	private AwsKmsEncryptionScheme es;
	private AwsKmsCredentialSet cs;
	private SecretKeyInfoFactory skiFactory;
	@SuppressWarnings("unused")
	private String encryptionKeyName;

	@org.junit.Before
	public void setUp() throws IOException {
		es = getEncryptionScheme();
		cs = getCredentialSet();
		skiFactory = es.getSecretKeyInfoFactory(cs,
				es.getKeyEncryptionAlgorithm(), Collections.emptyMap());
		encryptionKeyName =
			AwsKmsProperties.getMasterKeyId(cs.getProperties());
	}

	// Encrypt and check various documents using StAX
	@org.junit.Test
	public void testStAXEncryption() throws Exception {

		List<String> errors = new ArrayList<>();
		for (Object[] td : TestData.getTestData()) {

			// Check the test data
			Assert.assertTrue(td != null && td.length == 2);
			final String docName = (String) td[0];
			final QName docRoot = (QName) td[1];
			Assert.assertTrue(checkNodeCount(docName, docRoot, 1));

			try {
				// Encrypt a document using StAX
				final InputStream clearSource =
					CLASS_LOADER.getResourceAsStream(docName);
				final QName root = null;
				final String encoding = "UTF-8";
				final SecretKeyInfo ski = skiFactory.createSessionKey();
				// final String encryptionKeyName =
				// AwsKmsProperties.getMasterKeyId(cs.getProperties());
				// final XMLSecurityProperties encryptProperties =
				// prepareAwsKmsEncryptionProperties(docEncAlgo, ski,
				// keyEncAlgo, encryptionKeyName);
				// final XMLEncryptOutputProcessor encryptOutputProcessor =
				// new AwsKmsEncryptOutputProcessor();
				final XMLSecurityProperties encryptProperties =
					prepareWrappedEncryptionProperties(docEncAlgo, ski);
				final XMLEncryptOutputProcessor encryptOutputProcessor =
					new XMLEncryptOutputProcessor();
				final byte[] encryptedBytes =
					encryptEntireDocUsingStAX(clearSource, encoding,
							encryptProperties, encryptOutputProcessor);
				printXMLBytes(encryptedBytes, encoding, System.out);

				// Decrypt using StAX
				final InputStream encryptedSource =
					new ByteArrayInputStream(encryptedBytes);
				// final XMLSecurityProperties decryptProperties =
				// prepareAwsKmsDecryptionProperties(docEncAlgo, ski, encoding,
				// keyEncAlgo);
				// final byte[] decryptedBytes = decryptEntireDocUsingStAX(
				// encryptedSource, encoding, decryptProperties);
				// Set up the Configuration
				XMLSecurityProperties properties =
					prepareWrappedDecryptionProperties(docEncAlgo, ski);
				final byte[] decryptedBytes = decryptEntireDocUsingStAX(
						encryptedSource, encoding, properties);
				printXMLBytes(decryptedBytes, encoding, System.out);

				verifyStAXDecryption(docName, root, encoding, decryptedBytes);
			} catch (Throwable x) {
				String msg =
					"Failed to encrypt implicit root '" + docRoot.getLocalPart()
							+ "' in '" + docName + "' with wrapping key";
				msg += ": " + x.toString();
				errors.add(msg);
			}
		}
		if (errors.size() > 0) {
			final String INDENT = "   ";
			StringBuilder sb = new StringBuilder();
			sb.append("Errors: ").append(errors.size()).append(TestUtils.EOL);
			for (String error : errors) {
				sb.append(INDENT).append(error).append(TestUtils.EOL);
			}
			String msg = sb.toString();
			fail(msg);
		}
	}

	private void verifyStAXDecryption(String docName, QName root, String encoding,
			byte[] decryptedBytes) {
		// TODO Auto-generated method stub

	}

	static XMLSecurityProperties prepareWrappedDecryptionProperties(
			String docEncAlgo, SecretKeyInfo ski) {
		XMLSecurityProperties properties = new XMLSecurityProperties();
		List<XMLSecurityConstants.Action> actions =
			new ArrayList<XMLSecurityConstants.Action>();
		actions.add(XMLSecurityConstants.ENCRYPT);
		properties.setActions(actions);
		final SecretKey decryptingKey =
			KeyUtils.prepareSecretKey(docEncAlgo, ski.getKey());
		properties.setDecryptionKey(decryptingKey);
		return properties;
	}

	static XMLSecurityProperties prepareAwsKmsDecryptionProperties(
			String docEncAlgo, SecretKeyInfo ski, String keyEncAlgo,
			String encryptionKeyName) {
		XMLSecurityProperties properties = new XMLSecurityProperties();
		return properties;
	}

	byte[] decryptEntireDocUsingStAX(InputStream encryptedSource,
			String encoding, XMLSecurityProperties decryptProperties)
			throws XMLStreamException, IOException, XMLSecurityException {

		InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(decryptProperties);
		XMLInputFactory xmlInputFactory = XMLInputFactory.newInstance();
		final XMLStreamReader xmlStreamReader =
			xmlInputFactory.createXMLStreamReader(encryptedSource);
		// TestSecurityEventListener eventListener = new
		// TestSecurityEventListener();
		XMLStreamReader securityStreamReader =
			inboundXMLSec.processInMessage(xmlStreamReader, null, null);

		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		XMLOutputFactory xmlOutputFactory = XMLOutputFactory.newFactory();
		XMLStreamWriter xmlStreamWriter =
			xmlOutputFactory.createXMLStreamWriter(baos);

		XMLBorrowedUtils.writeAll(securityStreamReader, xmlStreamWriter);
		xmlStreamWriter.close();
		encryptedSource.close();
		byte[] retVal = baos.toByteArray();
		return retVal;
	}

}
