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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.Properties;

import javax.crypto.SecretKey;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.stream.util.XMLEventAllocator;

import org.apache.xml.security.stax.ext.InboundXMLSec;
import org.apache.xml.security.stax.ext.OutboundXMLSec;
import org.apache.xml.security.stax.ext.SecurePart;
import org.apache.xml.security.stax.ext.XMLSec;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import com.choicemaker.utilcopy01.KeyUtils;
import com.choicemaker.utilcopy01.SystemPropertyUtils;

/**
 * These tests require {#link AwsKmsProperties a property file} that defines
 * {@link AwsKmsProperties#hasAwsParameters(Properties) required AWS KMS
 * parameters}.
 * 
 * @see AwsKmsProperties
 */
public class StreamEncryptorDecryptorTest {

	private static final String EOL = SystemPropertyUtils.PV_LINE_SEPARATOR;

	public static final int BUFFER_SIZE = 1000;

	static {
		org.apache.xml.security.Init.init();
	}

	@Test
	public void testStreamEncryptorDecryptor() throws Exception {

		final String TEST = "testStreamEncryptorDecryptor";

		for (Object[] td : TestData.getTestData()) {

			// Check the test data
			Assert.assertTrue(td != null && td.length == 2);
			final String docName = (String) td[0];
			final QName docRoot = (QName) td[1];
			Assert.assertTrue(checkNodes(docName, docRoot, 1));
			
			// Configure encryption/decryption parameters
			final AwsKmsEncryptionScheme es = getEcryptionScheme();
			final AwsKmsCredentialSet cs = getCredentialSet();
			final String keyEncAlgo = DefaultAlgorithms.DECLARED_KEY_ENCRYPTION;
			final String docEncAlgo =
				DefaultAlgorithms.DEFAULT_DOC_ENCRYPT_ALGORITHM;
			final SecretKeyInfoFactory skiFactory = es.getSecretKeyInfoFactory(cs,
					es.getKeyEncryptionAlgorithm(), Collections.emptyMap());
			final SecretKeyInfo ski = skiFactory.createSessionKey();

			// Encrypt the test data
			InputStream is =
				this.getClass().getClassLoader().getResourceAsStream(docName);
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			StreamEncryptor.encrypt(is, keyEncAlgo, docEncAlgo, baos, ski);

			// Check the encrypted bytes
			byte[] encrypted = baos.toByteArray();
			String strEncrypted = new String(encrypted, "UTF-8");
			System.out.println(TEST + " Encrypted: " + strEncrypted + EOL);
			Assert.assertTrue(checkNodes(encrypted, docRoot, 0));

			// Decrypt the test data
			is = new ByteArrayInputStream(encrypted);
			ByteArrayOutputStream baosClear = new ByteArrayOutputStream();
			StreamDecryptor.decrypt(is, keyEncAlgo, docEncAlgo, baosClear, ski);

			// Check the decrypted bytes
			byte[] decrypted = baosClear.toByteArray();
			String strDecrypted = new String(decrypted, "UTF-8");
			System.out.println(TEST + " Decrypted: " + strDecrypted + EOL);
			Assert.assertTrue(checkNodes(decrypted, docRoot, 1));
		}

	}

	@Test
	public void testXMLInboundOutboundXMLSec() throws Exception {

		for (Object[] td : TestData.getTestData()) {

			Assert.assertTrue(td != null && td.length == 2);
			final String docName = (String) td[0];
			final QName docRoot = (QName) td[1];
			Assert.assertTrue(checkNodes(docName, docRoot, 1));

			final XMLInputFactory xmlInputFactory0 =
				XMLInputFactory.newInstance();

			final XMLInputFactory xmlInputFactory1 =
				XMLInputFactory.newInstance();

			final XMLOutputFactory xmlOutputFactory =
				XMLOutputFactory.newInstance();

			AwsKmsCredentialSet ec = getCredentialSet();
			AwsKmsEncryptionScheme es = getEcryptionScheme();
			final SecretKey secretKey = createSecretKey(es, ec);

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
			Assert.assertTrue(checkNodes(encrypted, docRoot, 0));
			String strEncrypted = new String(encrypted, "UTF-8");
			System.out.println("Encrypted: " + strEncrypted + EOL);

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
			Assert.assertTrue(checkNodes(decrypted, docRoot, 1));
			String strDecrypted = new String(decrypted, "UTF-8");
			System.out.println("Decrypted: " + strDecrypted + EOL);
		}

	}

	private AwsKmsCredentialSet getCredentialSet() throws IOException {
		String credentialName = "alice";
		AwsKmsCredentialSet retVal = new AwsKmsCredentialSet(credentialName);
		return retVal;
	}

	private AwsKmsEncryptionScheme getEcryptionScheme() {
		AwsKmsEncryptionScheme retVal = new AwsKmsEncryptionScheme();
		return retVal;
	}

	private SecretKey createSecretKey(AwsKmsEncryptionScheme encScheme,
			AwsKmsCredentialSet encCredentials) throws IOException {
		SecretKeyInfoFactory skiFactory =
			createSKIFactory(encCredentials, encScheme);
		SecretKeyInfo ski = skiFactory.createSessionKey();
		String docEncAlgo = DefaultAlgorithms.DEFAULT_DOC_ENCRYPT_ALGORITHM;
		return createSecretKey(ski, docEncAlgo);
	}

	private SecretKey createSecretKey(SecretKeyInfo ski, String docEncAlgo) {
		byte[] rawKey = ski.getKey();
		final SecretKey retVal = KeyUtils.prepareSecretKey(docEncAlgo, rawKey);
		return retVal;
	}

	private static SecretKeyInfoFactory createSKIFactory(
			AwsKmsCredentialSet encCredentials,
			AwsKmsEncryptionScheme encScheme) throws IOException {
		// Create the SecretKey that will encrypt the document
		SecretKeyInfoFactory retVal = encScheme.getSecretKeyInfoFactory(
				encCredentials, encScheme.getKeyEncryptionAlgorithm(),
				Collections.emptyMap());
		return retVal;
	}

	private boolean checkNodes(String resourceName, QName root,
			int expectedCount) {
		InputStream is =
			this.getClass().getClassLoader().getResourceAsStream(resourceName);
		return checkNodes(is, root, expectedCount);
	}

	private static boolean checkNodes(byte[] bytes, QName root,
			int expectedCount) {
		InputStream is = new ByteArrayInputStream(bytes);
		return checkNodes(is, root, expectedCount);
	}

	private static boolean checkNodes(InputStream is, QName root,
			int expectedCount) {
		boolean retVal = false;
		if (is != null) {
			try {
				final DocumentBuilder documentBuilder =
					XMLUtils.createDocumentBuilder(false);
				Document doc = documentBuilder.parse(is);
				retVal = checkNodes(doc, root, expectedCount);
			} catch (Exception x) {
				assert retVal == false;
			}
		}
		return retVal;
	}

	private static boolean checkNodes(Document doc, QName root,
			int expectedCount) {
		String nsURI = root.getNamespaceURI();
		String lname = root.getLocalPart();
		NodeList nodes = doc.getElementsByTagNameNS(nsURI, lname);
		boolean retVal = nodes.getLength() == expectedCount;
		return retVal;
	}

}
