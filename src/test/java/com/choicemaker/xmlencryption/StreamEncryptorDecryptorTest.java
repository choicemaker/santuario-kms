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

import static com.choicemaker.xmlencryption.TestUtils.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.Collections;
import java.util.Properties;

import javax.crypto.SecretKey;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;

import org.apache.xml.security.stax.ext.InboundXMLSec;
import org.apache.xml.security.stax.ext.OutboundXMLSec;
import org.apache.xml.security.stax.ext.SecurePart;
import org.apache.xml.security.stax.ext.XMLSec;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.junit.Assert;
import org.junit.Test;

import com.choicemaker.utilcopy01.KeyUtils;

/**
 * These tests require {#link AwsKmsProperties a property file} that defines
 * {@link AwsKmsProperties#hasAwsParameters(Properties) required AWS KMS
 * parameters}.
 * 
 * @see AwsKmsProperties
 */
public class StreamEncryptorDecryptorTest {

	public static final int BUFFER_SIZE = 1000;

	static {
		org.apache.xml.security.Init.init();
	}

	@Test
	public void testStreamEncryptDecryptElement() throws Exception {

		final String TEST = "testStreamEncryptorDecryptor";

		for (Object[] td : TestData.getTestData()) {

			// Check the test data
			Assert.assertTrue(td != null && td.length == 2);
			final String docName = (String) td[0];
			final QName docRoot = (QName) td[1];
			Assert.assertTrue(TestUtils.checkNodeCount(docName, docRoot, 1));

			// Configure encryption/decryption parameters
			final AwsKmsEncryptionScheme es = getEncryptionScheme();
			final AwsKmsCredentialSet cs = getCredentialSet();
			final String keyEncAlgo = DefaultAlgorithms.DECLARED_KEY_ENCRYPTION;
			final String docEncAlgo =
				DefaultAlgorithms.DEFAULT_DOC_ENCRYPT_ALGO;
			final SecretKeyInfoFactory skiFactory = es.getSecretKeyInfoFactory(
					cs, es.getKeyEncryptionAlgorithm(), Collections.emptyMap());
			final SecretKeyInfo ski = skiFactory.createSessionKey();

			// Encrypt the entire test data
			final boolean CONTENT_ONLY = false;
			InputStream is =
				this.getClass().getClassLoader().getResourceAsStream(docName);
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			StreamEncryptor.encrypt(is, keyEncAlgo, docEncAlgo, baos, ski,
					CONTENT_ONLY);

			// Check the encrypted bytes
			byte[] encrypted = baos.toByteArray();
			String strEncrypted = new String(encrypted, "UTF-8");
			System.out.println(
					TEST + " Encrypted: " + strEncrypted + TestUtils.EOL);
			Assert.assertTrue(TestUtils.checkNodeCount(encrypted, docRoot, 0));

			// Decrypt the test data
			is = new ByteArrayInputStream(encrypted);
			ByteArrayOutputStream baosClear = new ByteArrayOutputStream();
			StreamDecryptor.decrypt(is, keyEncAlgo, docEncAlgo, baosClear, ski);

			// Check the decrypted bytes
			byte[] decrypted = baosClear.toByteArray();
			String strDecrypted = new String(decrypted, "UTF-8");
			System.out.println(
					TEST + " Decrypted: " + strDecrypted + TestUtils.EOL);
			Assert.assertTrue(TestUtils.checkNodeCount(decrypted, docRoot, 1));
		}

	}

	@Test
	public void testXMLInboundOutboundXMLSec() throws Exception {

		// final String keyEncAlgo = DefaultAlgorithms.DECLARED_KEY_ENCRYPTION;
		final String docEncAlgo = DefaultAlgorithms.DEFAULT_DOC_ENCRYPT_ALGO;

		for (Object[] td : TestData.getTestData()) {

			Assert.assertTrue(td != null && td.length == 2);
			final String docName = (String) td[0];
			final QName docRoot = (QName) td[1];
			Assert.assertTrue(TestUtils.checkNodeCount(docName, docRoot, 1));

			final XMLInputFactory xmlInputFactory0 =
				XMLInputFactory.newInstance();

			final XMLInputFactory xmlInputFactory1 =
				XMLInputFactory.newInstance();

			final XMLOutputFactory xmlOutputFactory =
				XMLOutputFactory.newInstance();

			// Configure encryption/decryption parameters
			final AwsKmsEncryptionScheme es = getEncryptionScheme();
			final AwsKmsCredentialSet cs = getCredentialSet();
			final SecretKeyInfoFactory skiFactory = es.getSecretKeyInfoFactory(
					cs, es.getKeyEncryptionAlgorithm(), Collections.emptyMap());
			final SecretKeyInfo ski = skiFactory.createSessionKey();
			final SecretKey secretKey =
				KeyUtils.prepareSecretKey(docEncAlgo, ski.getKey());

			final XMLSecurityProperties encryptProperties =
				StreamEncryptor.getEncryptionSecurityProperies(secretKey);
			SecurePart.Modifier modifier = SecurePart.Modifier.Element;
			SecurePart securePart = new SecurePart("", modifier);
			securePart.setSecureEntireRequest(true);
			encryptProperties.addEncryptionPart(securePart);

			final XMLSecurityProperties decryptProperties =
				StreamDecryptor.getDecryptionSecurityProperies(secretKey);

			// Encrypt
			InputStream isClear =
				this.getClass().getClassLoader().getResourceAsStream(docName);
			XMLStreamReader xmlClearReader =
				xmlInputFactory0.createXMLStreamReader(isClear);
			ByteArrayOutputStream baosCypher = new ByteArrayOutputStream();
			final OutboundXMLSec outboundCypher =
				XMLSec.getOutboundXMLSec(encryptProperties);
			XMLStreamWriter xmlCypherWriter =
				outboundCypher.processOutMessage(baosCypher, "UTF-8");
			XMLBorrowedUtils.writeAll(xmlClearReader, xmlCypherWriter);
			xmlCypherWriter.close();
			byte[] encrypted = baosCypher.toByteArray();
			Assert.assertTrue(TestUtils.checkNodeCount(encrypted, docRoot, 0));
			String strEncrypted = new String(encrypted, "UTF-8");
			System.out.println("Encrypted: " + strEncrypted + TestUtils.EOL);

			// Decrypt
			InputStream isCypher = new ByteArrayInputStream(encrypted);
			XMLStreamReader xmlStreamReaderCypher =
				xmlInputFactory1.createXMLStreamReader(isCypher);
			final InboundXMLSec inboundClear =
				XMLSec.getInboundWSSec(decryptProperties);
			xmlStreamReaderCypher =
				inboundClear.processInMessage(xmlStreamReaderCypher);
			ByteArrayOutputStream baosClear = new ByteArrayOutputStream();
			XMLStreamWriter xmlStreamWriterClear =
				xmlOutputFactory.createXMLStreamWriter(baosClear);
			XMLBorrowedUtils.writeAll(xmlStreamReaderCypher,
					xmlStreamWriterClear);
			xmlStreamWriterClear.close();

			byte[] decrypted = baosClear.toByteArray();
			Assert.assertTrue(TestUtils.checkNodeCount(decrypted, docRoot, 1));
			String strDecrypted = new String(decrypted, "UTF-8");
			System.out.println("Decrypted: " + strDecrypted + TestUtils.EOL);
		}

	}

}
