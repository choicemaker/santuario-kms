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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.crypto.SecretKey;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;

import org.apache.xml.security.stax.ext.OutboundXMLSec;
import org.apache.xml.security.stax.ext.SecurePart;
import org.apache.xml.security.stax.ext.XMLSec;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
//import org.apache.xml.security.test.stax.utils.XMLSecEventAllocator;

import com.choicemaker.utilcopy01.KeyUtils;
import com.choicemaker.utilcopy01.Precondition;

public class StreamEncryptor {

	// private static final Logger logger =
	// Logger.getLogger(StreamEncryptor.class.getName());

	static {
		org.apache.xml.security.Init.init();
	}

	// private static void encryptElement(Document doc, Element
	// elementToEncrypt,
	// String docEncAlgo, SecretKey secretKey, KeyInfo keyInfo)
	// throws XMLEncryptionException {
	// final XMLCipher xmlCipher = XMLCipher.getInstance(docEncAlgo);
	// xmlCipher.init(XMLCipher.ENCRYPT_MODE, secretKey);
	// EncryptedData encData = xmlCipher.getEncryptedData();
	// final String xencEncryptedDataId = generateEncryptedDataId();
	// encData.setId(xencEncryptedDataId);
	// encData.setKeyInfo(keyInfo);
	// final boolean content = true;
	// logger.fine(
	// "Before encryption: " + SystemPropertyUtils.PV_LINE_SEPARATOR
	// + XMLPrettyPrint.print(elementToEncrypt));
	// try {
	// xmlCipher.doFinal(doc, elementToEncrypt, content);
	// } catch (XMLEncryptionException e) {
	// logger.severe(e.toString());
	// throw e;
	// } catch (Exception e) {
	// logger.severe(e.toString());
	// String msg = "Failed to encrypt element '" + elementToEncrypt
	// + "': " + e.getClass().getSimpleName();
	// throw new XMLEncryptionException(msg, e);
	// }
	// logger.fine("After encryption: " + SystemPropertyUtils.PV_LINE_SEPARATOR
	// + XMLPrettyPrint.print(elementToEncrypt));
	// }

	// private static String generateEncryptedDataId() {
	// String retVal = IDGenerator.generateID("ED-");
	// return retVal;
	// }

//	private final CredentialSet credential;
//	private final EncryptionScheme scheme;
//	private final SecretKeyInfoFactory skiFactory;
	// private final EncryptedKeyFactory ekFactory = new EncryptedKeyFactory();
	
	private StreamEncryptor() {}

//	public StreamEncryptor(EncryptionScheme es, CredentialSet cs) {
//		Precondition.assertNonNullArgument("null credentials", cs);
//		Precondition.assertNonNullArgument("null scheme", es);
//
//		credential = cs;
//		scheme = es;
//		skiFactory = getSecretKeyInfoFactory(es, cs);
//	}

//	public CredentialSet getCredential() {
//		return credential;
//	}
//
//	public EncryptionScheme getScheme() {
//		return scheme;
//	}

	// private KeyInfo createKeyInfo(Document document, Element encKey) {
	//
	// KeyInfo keyInfo = new KeyInfo(document);
	// keyInfo.addUnknownElement(encKey);
	// Element keyInfoElement = keyInfo.getElement();
	// keyInfoElement.setAttributeNS(WSS4JConstants.XMLNS_NS,
	// "xmlns:" + WSS4JConstants.SIG_PREFIX, WSS4JConstants.SIG_NS);
	//
	// return keyInfo;
	// }

//	public void encrypt(InputStream sourceDocument, OutputStream outputStream)
//			throws Exception {
//		encrypt(sourceDocument, DefaultAlgorithms.DECLARED_KEY_ENCRYPTION,
//				DefaultAlgorithms.DEFAULT_DOC_ENCRYPT_ALGORITHM, outputStream);
//	}

	/**
	 * Encrypts the content of the root element of an XML document.
	 *
	 * @param sourceDocument
	 *            the document to be encrypted. The content of the root element
	 *            will be replaced with EncryptedData.
	 * @param keyEncAlgo
	 *            the key encryption algorithm; see
	 *            {@link DefaultAlgorithms#DECLARED_KEY_ENCRYPTION} for the
	 *            recommended algorithm.
	 * @param docEncAlgo
	 *            the name of the currently selected symmetric document
	 *            encryption algorithm; see {@link WSConstants#TRIPLE_DES
	 *            TRIPLE_DES}, {@link WSConstants#AES_128 AES_128},
	 *            {@link WSConstants#AES_192 AES_192}, or
	 *            {@link WSConstants#AES_256 AES_256}.
	 * @throws Exception
	 */
//	public void encrypt(final InputStream sourceDocument, String keyEncAlgo,
//			String docEncAlgo, OutputStream outputStream) throws Exception {
//		encrypt(sourceDocument, keyEncAlgo, docEncAlgo, outputStream,
//				skiFactory);
//	}

	public static void encrypt(final InputStream sourceDocument,
			String keyEncAlgo, String docEncAlgo, OutputStream outputStream,
			SecretKeyInfo ski) throws Exception {

		// Preconditions
		Precondition.assertNonNullArgument("null document", sourceDocument);
		Precondition.assertNonEmptyString(
				"null or blank key encryption algorithm", keyEncAlgo);
		Precondition.assertNonEmptyString(
				"null or blank document encryption algorithm", docEncAlgo);

		final XMLInputFactory xmlInputFactory = XMLInputFactory.newInstance();

		// final XMLEventAllocator eventAllocator = getEventAllocator();
		// final XMLInputFactory xmlInputFactory1 =
		// XMLInputFactory.newInstance();
		// xmlInputFactory1.setEventAllocator(eventAllocator);

		// Create the SecretKey that will encrypt the document
//		SecretKeyInfo ski = skiFactory.createSessionKey();
		final SecretKey secretKey =
			KeyUtils.prepareSecretKey(docEncAlgo, ski.getKey());

		// // Create the encrypted key element that will replace the root
		// content
		// Element ek = ekFactory.createEncryptedKeyElement(sourceDocument,
		// keyEncAlgo, ski);
		// final KeyInfo keyInfo = createKeyInfo(sourceDocument, ek);
		//
		// // Encrypt the content of the root element
		// encryptElement(sourceDocument, root, docEncAlgo, secretKey, keyInfo);

		final XMLSecurityProperties encryptProperties =
			StreamEncryptor.getEncryptionSecurityProperies(secretKey);
		SecurePart.Modifier modifier = SecurePart.Modifier.Element;
		SecurePart securePart = new SecurePart("", modifier);
		securePart.setSecureEntireRequest(true);
		encryptProperties.addEncryptionPart(securePart);

		// Encrypt
		XMLStreamReader xmlStreamReader =
			xmlInputFactory.createXMLStreamReader(sourceDocument);
		final OutboundXMLSec outbound =
			XMLSec.getOutboundXMLSec(encryptProperties);
		XMLStreamWriter xmlStreamWriter =
			outbound.processOutMessage(outputStream, "UTF-8");
		XMLBorrowedUtils.writeAll(xmlStreamReader, xmlStreamWriter);
		xmlStreamWriter.close();
	}

	public static XMLSecurityProperties getEncryptionSecurityProperies(
			SecretKey secretKey) {
		XMLSecurityProperties retVal = new XMLSecurityProperties();
		retVal.setEncryptionKey(secretKey);
		List<XMLSecurityConstants.Action> actions;
		actions = new ArrayList<XMLSecurityConstants.Action>();
		actions.add(XMLSecurityConstants.ENCRYPT);
		retVal.setActions(actions);
		return retVal;
	}

//	public static XMLSecurityProperties getDecryptionSecurityProperies(
//			SecretKey secretKey) throws IOException {
//		XMLSecurityProperties retVal = new XMLSecurityProperties();
//		retVal.setDecryptionKey(secretKey);
//		return retVal;
//	}
//
}
