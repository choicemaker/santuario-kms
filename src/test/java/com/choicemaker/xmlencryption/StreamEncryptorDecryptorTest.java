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
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
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
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.Assert;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import com.choicemaker.utilcopy01.KeyUtils;

/**
 * These tests require {#link AwsKmsProperties a property file} that defines
 * {@link AwsKmsProperties#hasAwsParameters(Properties) required AWS KMS
 * parameters}.
 * 
 * @see AwsKmsProperties
 */
public class StreamEncryptorDecryptorTest {

	// private static final Logger logger =
	// Logger.getLogger(StreamEncryptorDecryptorTest2.class.getName());

	public static final int BUFFER_SIZE = 1000;

	static {
		// Security.addProvider(new
		// org.bouncycastle.jce.provider.BouncyCastleProvider());
		org.apache.xml.security.Init.init();
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

			final XMLEventAllocator eventAllocator = getEventAllocator();
			final XMLInputFactory xmlInputFactory1 =
				XMLInputFactory.newInstance();
			xmlInputFactory1.setEventAllocator(eventAllocator);

			final XMLOutputFactory xmlOutputFactory =
				XMLOutputFactory.newInstance();

			final SecretKey secretKey = createSecretKey();

			final XMLSecurityProperties encryptProperties =
				getEncryptionSecurityProperies(secretKey);
			SecurePart.Modifier modifier = SecurePart.Modifier.Element;
			SecurePart securePart = new SecurePart("", modifier);
			securePart.setSecureEntireRequest(true);
			encryptProperties.addEncryptionPart(securePart);

			final XMLSecurityProperties decryptProperties =
				getDecryptionSecurityProperies(secretKey);

			final OutboundXMLSec outbound =
				XMLSec.getOutboundXMLSec(encryptProperties);
			final InboundXMLSec inbound =
				XMLSec.getInboundWSSec(decryptProperties);

			InputStream is;
			XMLStreamReader xmlStreamReader;
			ByteArrayOutputStream baos;
			XMLStreamWriter xmlStreamWriter;

			// Encrypt
			is = this.getClass().getClassLoader().getResourceAsStream(docName);
			xmlStreamReader = xmlInputFactory0.createXMLStreamReader(is);
			baos = new ByteArrayOutputStream();
			xmlStreamWriter = outbound.processOutMessage(baos, "UTF-8");
			XMLBorrowedUtils.writeAll(xmlStreamReader, xmlStreamWriter);
			xmlStreamWriter.close();
			byte[] encrypted = baos.toByteArray();
			Assert.assertTrue(checkNodes(encrypted, docRoot, 0));
			String strEncrypted = new String(encrypted, "UTF-8");
			System.out.println("Encrypted: " + strEncrypted);

			// Decrypt
			is = new ByteArrayInputStream(encrypted);
			xmlStreamReader = xmlInputFactory1.createXMLStreamReader(is);
			xmlStreamReader = inbound.processInMessage(xmlStreamReader);
			baos = new ByteArrayOutputStream();
			xmlStreamWriter = xmlOutputFactory.createXMLStreamWriter(baos);
			XMLBorrowedUtils.writeAll(xmlStreamReader, xmlStreamWriter);
			xmlStreamWriter.close();

			byte[] decrypted = baos.toByteArray();
			Assert.assertTrue(checkNodes(decrypted, docRoot, 1));
			String strDecrypted = new String(decrypted, "UTF-8");
			System.out.println("Decrypted: " + strDecrypted);
		}

	}

	private XMLEventAllocator getEventAllocator() throws Exception {
		return new XMLSecEventAllocator();
	}

	private XMLSecurityProperties getEncryptionSecurityProperies(
			SecretKey secretKey) {
		XMLSecurityProperties retVal = new XMLSecurityProperties();
		retVal.setEncryptionKey(secretKey);
		List<XMLSecurityConstants.Action> actions;
		actions = new ArrayList<XMLSecurityConstants.Action>();
		actions.add(XMLSecurityConstants.ENCRYPT);
		retVal.setActions(actions);
		return retVal;
	}

	private XMLSecurityProperties getDecryptionSecurityProperies(
			SecretKey secretKey) throws IOException {
		XMLSecurityProperties retVal = new XMLSecurityProperties();
		retVal.setDecryptionKey(secretKey);
		return retVal;
	}

	private SecretKey createSecretKey() throws IOException {
		// Create the SecretKey that will encrypt the document
		String credentialName = "alice";
		AwsKmsEncryptionScheme encScheme = new AwsKmsEncryptionScheme();
		AwsKmsCredentialSet encCredentials =
			new AwsKmsCredentialSet(credentialName);
		SecretKeyInfoFactory skiFactory = encScheme.getSecretKeyInfoFactory(
				encCredentials, encScheme.getKeyEncryptionAlgorithm(),
				Collections.emptyMap());
		SecretKeyInfo ski = skiFactory.createSessionKey();
		String docEncAlgo = DefaultAlgorithms.DEFAULT_DOC_ENCRYPT_ALGORITHM;
		byte[] rawKey = ski.getKey();
		final SecretKey retVal = KeyUtils.prepareSecretKey(docEncAlgo, rawKey);
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
