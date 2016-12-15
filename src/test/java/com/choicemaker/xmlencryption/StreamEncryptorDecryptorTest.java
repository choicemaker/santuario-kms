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
import javax.xml.XMLConstants;
import javax.xml.namespace.QName;
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

		final XMLEventAllocator eventAllocator = getEventAllocator();
		final XMLInputFactory xmlInputFactory = XMLInputFactory.newInstance();
		xmlInputFactory.setEventAllocator(eventAllocator);

		final XMLOutputFactory xmlOutputFactory =
			XMLOutputFactory.newInstance();

		final SecretKey secretKey = createSecretKey();

		final XMLSecurityProperties encryptProperties =
			getEncryptionSecurityProperies(secretKey);
		SecurePart.Modifier modifier = SecurePart.Modifier.Element;
//		List<QName> namesToEncrypt = new ArrayList<QName>();
//		QName paymentInfo = new QName("urn:example:po", "PaymentInfo");
//		namesToEncrypt.add(paymentInfo);
//		for (QName nameToEncrypt : namesToEncrypt) {
//			SecurePart securePart = new SecurePart(nameToEncrypt, modifier);
//			encryptProperties.addEncryptionPart(securePart);
//		}
//		QName empty = new QName(XMLConstants.NULL_NS_URI, "");
		SecurePart securePart = new SecurePart("", modifier);
		securePart.setSecureEntireRequest(true);
		encryptProperties.addEncryptionPart(securePart);

		final XMLSecurityProperties decryptProperties =
			getDecryptionSecurityProperies(secretKey);

		for (String plaintext : TestData.getTestData()) {

			final OutboundXMLSec outbound =
					XMLSec.getOutboundXMLSec(encryptProperties);
			final InboundXMLSec inbound = XMLSec.getInboundWSSec(decryptProperties);

			InputStream is;
			XMLStreamReader xmlStreamReader;
			ByteArrayOutputStream baos;
			XMLStreamWriter xmlStreamWriter;

			// Encrypt
			is = this.getClass().getClassLoader()
					.getResourceAsStream(plaintext);
			xmlStreamReader = xmlInputFactory.createXMLStreamReader(is);
			baos = new ByteArrayOutputStream();
			xmlStreamWriter = outbound.processOutMessage(baos, "UTF-8");
			XMLBorrowedUtils.writeAll(xmlStreamReader, xmlStreamWriter);
			xmlStreamWriter.close();
			byte[] encrypted = baos.toByteArray();
			String strEncrypted = new String(encrypted, "UTF-8");
			System.out.println("Encrypted: " + strEncrypted);

			// Decrypt
			is = new ByteArrayInputStream(encrypted);
			xmlStreamReader = xmlInputFactory.createXMLStreamReader(is);
			xmlStreamReader = inbound.processInMessage(xmlStreamReader);
			baos = new ByteArrayOutputStream();
			xmlStreamWriter = xmlOutputFactory.createXMLStreamWriter(baos);
			XMLBorrowedUtils.writeAll(xmlStreamReader, xmlStreamWriter);
			xmlStreamWriter.close();

			byte[] decrypted = baos.toByteArray();
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

	// @Test
	// public void testEncryptDecryptDocument() throws Exception {
	//
	// String credentialName = "alice";
	// AwsKmsEncryptionScheme encScheme = new AwsKmsEncryptionScheme();
	// AwsKmsCredentialSet encCredentials =
	// new AwsKmsCredentialSet(credentialName);
	//
	// final DocumentDecryptor decryptor =
	// new DocumentDecryptor(encScheme, encCredentials);
	// final DocumentEncryptor encryptor =
	// new DocumentEncryptor(encScheme, encCredentials);
	//
	// for (String plaintext : TestData.getTestData()) {
	//
	// InputStream sourceDocument =
	// this.getClass().getClassLoader().getResourceAsStream(plaintext);
	// DocumentBuilder builder = XMLUtils.createDocumentBuilder(false);
	// final Document original = builder.parse(sourceDocument);
	// final Element originalRoot = original.getDocumentElement();
	// final String originalAsString = XMLPrettyPrint.print(original);
	// logger.info("original: " + originalAsString);
	//
	// // Get the tag names of the elements that are immediate children
	// // of the root.
	// Set<String> tagNamesClearText = new LinkedHashSet<>();
	// NodeList nl = originalRoot.getChildNodes();
	// final int childCount = nl.getLength();
	// assertTrue(childCount > 0);
	// for (int i = 0; i < childCount; i++) {
	// Node n = nl.item(i);
	// if (n instanceof Element) {
	// Element e = (Element) n;
	// String tagName = e.getTagName();
	// tagNamesClearText.add(tagName);
	// }
	// }
	// assertTrue(tagNamesClearText.size() > 0);
	//
	// // Encrypt a copy of the original document
	// final Document encrypted = builder.newDocument();
	// Node copiedRoot = encrypted.importNode(originalRoot, true);
	// encrypted.appendChild(copiedRoot);
	// encryptor.encrypt(encrypted);
	// final Element encryptedRoot = encrypted.getDocumentElement();
	// final String encryptedAsString = XMLPrettyPrint.print(encrypted);
	// logger.info("encrypted: " + encryptedAsString);
	//
	// // After encryption, the immediate children of the root should be
	// // exactly one EncryptedData element.
	// Set<String> tagNamesEncrypted = new LinkedHashSet<>();
	// NodeList nlEnc = encrypted.getDocumentElement().getChildNodes();
	// for (String tagName : tagNamesEncrypted) {
	// nlEnc = encrypted.getElementsByTagName(tagName);
	// assertTrue(nlEnc.getLength() == 1);
	// }
	// assertTrue(nlEnc.getLength() == 1);
	// Node n = nlEnc.item(0);
	// assertTrue(n instanceof Element);
	// Element e = (Element) n;
	// assertTrue("xenc:EncryptedData".equals(e.getTagName()));
	//
	// // Decrypt a copy of the encrypted document
	// final Document decrypted = builder.newDocument();
	// Node copiedRoot2 = decrypted.importNode(encryptedRoot, true);
	// decrypted.appendChild(copiedRoot2);
	// decryptor.decrypt(decrypted);
	// logger.info("decrypted: " + XMLPrettyPrint.print(decrypted));
	//
	// // After decryption, there should be least one immediate child of
	// // the root element for every document in the test data and there
	// // should be no EncryptedData elements
	// NodeList nlDec;
	// for (String tagName : tagNamesClearText) {
	// nlDec = decrypted.getElementsByTagName(tagName);
	// assertTrue(nlDec.getLength() > 0);
	// }
	// nlDec = decrypted.getElementsByTagName("xenc:EncryptedData");
	// assertTrue(nlDec.getLength() == 0);
	//
	// // The decrypted document should be the same as the original,
	// // excluding stuff like namespace prefixes, encoding, etc.
	// // (See the definition of 'similar' for the default XMLUnit
	// // difference evaluator.)
	// Diff diff =
	// DiffBuilder.compare(original).withTest(decrypted)
	// .ignoreComments().checkForSimilar().build();
	// final boolean hasDifferences = diff.hasDifferences();
	// if (hasDifferences) {
	// Iterable<Difference> differences = diff.getDifferences();
	// for (Difference d : differences) {
	// logger.warning(d.toString());
	// }
	// }
	// assertFalse(diff.toString(), hasDifferences);
	// }
	//
	// }

}