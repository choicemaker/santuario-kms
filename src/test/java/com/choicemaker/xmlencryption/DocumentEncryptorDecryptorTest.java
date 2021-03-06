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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.InputStream;
import java.util.LinkedHashSet;
import java.util.Properties;
import java.util.Set;
import java.util.logging.Logger;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;

import org.apache.xml.security.utils.XMLUtils;
import org.junit.Assert;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xmlunit.builder.DiffBuilder;
import org.xmlunit.diff.Diff;
import org.xmlunit.diff.Difference;

/**
 * These tests require {#link AwsKmsProperties a property file} that defines
 * {@link AwsKmsProperties#hasAwsParameters(Properties) required AWS KMS
 * parameters}.
 * 
 * @see AwsKmsProperties
 */
public class DocumentEncryptorDecryptorTest {

	private static final Logger logger =
		Logger.getLogger(DocumentEncryptorDecryptorTest.class.getName());

	public static final int BUFFER_SIZE = 1000;

	@Test
	public void testEncryptDecryptDocument() throws Exception {

		final String TEST = "testEncryptDecryptDocument";

		String credentialName = "alice";
		AwsKmsEncryptionScheme encScheme = new AwsKmsEncryptionScheme();
		AwsKmsCredentialSet encCredentials =
			new AwsKmsCredentialSet(credentialName);

		final DocumentDecryptor decryptor =
			new DocumentDecryptor(encScheme, encCredentials);
		final DocumentEncryptor encryptor =
			new DocumentEncryptor(encScheme, encCredentials);

		for (Object[] td : TestData.getTestData()) {

			Assert.assertTrue(td != null && td.length == 2);
			final String docName = (String) td[0];
			final QName docRoot = (QName) td[1];

			InputStream sourceDocument =
				this.getClass().getClassLoader().getResourceAsStream(docName);
			DocumentBuilder builder = XMLUtils.createDocumentBuilder(false);
			final Document original = builder.parse(sourceDocument);

			final Element originalRoot = original.getDocumentElement();
			Assert.assertTrue(
					docRoot.getLocalPart().equals(originalRoot.getLocalName()));
			Assert.assertTrue(docRoot.getNamespaceURI()
					.equals(originalRoot.getNamespaceURI()));

			final String originalAsString = XMLPrettyPrint.print(original);
			logger.info("original: " + originalAsString);
			System.out.println(TEST + " Original: " + originalAsString + TestUtils.EOL);

			// Get the tag names of the elements that are immediate children
			// of the root.
			Set<String> tagNamesClearText = new LinkedHashSet<>();
			NodeList nl = originalRoot.getChildNodes();
			final int childCount = nl.getLength();
			assertTrue(childCount > 0);
			for (int i = 0; i < childCount; i++) {
				Node n = nl.item(i);
				if (n instanceof Element) {
					Element e = (Element) n;
					String tagName = e.getTagName();
					tagNamesClearText.add(tagName);
				}
			}
			assertTrue(tagNamesClearText.size() > 0);

			// Encrypt a copy of the original document
			final Document encrypted = builder.newDocument();
			Node copiedRoot = encrypted.importNode(originalRoot, true);
			encrypted.appendChild(copiedRoot);
			encryptor.encrypt(encrypted);
			final Element encryptedRoot = encrypted.getDocumentElement();

			final String encryptedAsString = XMLPrettyPrint.print(encrypted);
			logger.info("encrypted: " + encryptedAsString);
			System.out.println(TEST + " Encrypted: " + encryptedAsString + TestUtils.EOL);

			// After encryption, the immediate children of the root should be
			// exactly one EncryptedData element.
			Set<String> tagNamesEncrypted = new LinkedHashSet<>();
			NodeList nlEnc = encrypted.getDocumentElement().getChildNodes();
			for (String tagName : tagNamesEncrypted) {
				nlEnc = encrypted.getElementsByTagName(tagName);
				assertTrue(nlEnc.getLength() == 1);
			}
			assertTrue(nlEnc.getLength() == 1);
			Node n = nlEnc.item(0);
			assertTrue(n instanceof Element);
			Element e = (Element) n;
			assertTrue("xenc:EncryptedData".equals(e.getTagName()));

			// Decrypt a copy of the encrypted document
			final Document decrypted = builder.newDocument();
			Node copiedRoot2 = decrypted.importNode(encryptedRoot, true);
			decrypted.appendChild(copiedRoot2);
			decryptor.decrypt(decrypted);

			final String decryptedAsString = XMLPrettyPrint.print(decrypted);
			logger.info("decrypted: " + decryptedAsString);
			System.out.println(TEST + " Decrypted: " + decryptedAsString + TestUtils.EOL);

			// After decryption, there should be least one immediate child of
			// the root element for every document in the test data and there
			// should be no EncryptedData elements
			NodeList nlDec;
			for (String tagName : tagNamesClearText) {
				nlDec = decrypted.getElementsByTagName(tagName);
				assertTrue(nlDec.getLength() > 0);
			}
			nlDec = decrypted.getElementsByTagName("xenc:EncryptedData");
			assertTrue(nlDec.getLength() == 0);

			// The decrypted document should be the same as the original,
			// excluding stuff like namespace prefixes, encoding, etc.
			// (See the definition of 'similar' for the default XMLUnit
			// difference evaluator.)
			Diff diff = DiffBuilder.compare(original).withTest(decrypted)
					.ignoreComments().checkForSimilar().build();
			final boolean hasDifferences = diff.hasDifferences();
			if (hasDifferences) {
				Iterable<Difference> differences = diff.getDifferences();
				for (Difference d : differences) {
					logger.warning(d.toString());
				}
			}
			assertFalse(diff.toString(), hasDifferences);
		}

	}

}
