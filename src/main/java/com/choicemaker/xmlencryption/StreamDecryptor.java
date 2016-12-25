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
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.crypto.SecretKey;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;

import org.apache.xml.security.stax.ext.InboundXMLSec;
import org.apache.xml.security.stax.ext.OutboundXMLSec;
import org.apache.xml.security.stax.ext.SecurePart;
import org.apache.xml.security.stax.ext.XMLSec;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
//import org.apache.xml.security.test.stax.utils.XMLSecEventAllocator;

import com.choicemaker.utilcopy01.KeyUtils;
import com.choicemaker.utilcopy01.Precondition;

public class StreamDecryptor {

	// private static final Logger logger =
	// Logger.getLogger(StreamEncryptor.class.getName());

	static {
		org.apache.xml.security.Init.init();
	}

	private StreamDecryptor() {}

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
	public static void decrypt(final InputStream is,
			String keyEncAlgo, String docEncAlgo, OutputStream outputStream,
			SecretKeyInfo ski) throws Exception {

		// Preconditions
		Precondition.assertNonNullArgument("null input stream", is);
		Precondition.assertNonEmptyString(
				"null or blank key encryption algorithm", keyEncAlgo);
		Precondition.assertNonEmptyString(
				"null or blank document encryption algorithm", docEncAlgo);

		final SecretKey secretKey =
				KeyUtils.prepareSecretKey(docEncAlgo, ski.getKey());
		final XMLSecurityProperties decryptProperties =
			getDecryptionSecurityProperies(secretKey);
		final InboundXMLSec inbound =
			XMLSec.getInboundWSSec(decryptProperties);
		final XMLInputFactory xmlInputFactory =
			XMLInputFactory.newInstance();
		XMLStreamReader xmlStreamReader =
			xmlInputFactory.createXMLStreamReader(is);
		xmlStreamReader = inbound.processInMessage(xmlStreamReader);

		final XMLOutputFactory xmlOutputFactory =
			XMLOutputFactory.newInstance();
		XMLStreamWriter xmlStreamWriter =
			xmlOutputFactory.createXMLStreamWriter(outputStream);

		XMLBorrowedUtils.writeAll(xmlStreamReader, xmlStreamWriter);
		xmlStreamWriter.close();
	}

	public static XMLSecurityProperties getDecryptionSecurityProperies(
			SecretKey secretKey) throws IOException {
		XMLSecurityProperties retVal = new XMLSecurityProperties();
		retVal.setDecryptionKey(secretKey);
		return retVal;
	}

}
