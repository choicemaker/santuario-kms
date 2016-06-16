package com.choicemaker.xmlencryption;

import static com.choicemaker.xmlencryption.AwsKmsUtils.DEFAULT_AWS_KEY_ENCRYPTION_ALGORITHM;
import static org.junit.Assert.assertTrue;

import java.io.InputStream;
import java.util.LinkedHashSet;
import java.util.Set;

import javax.xml.parsers.DocumentBuilder;

import org.apache.xml.security.utils.XMLUtils;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class DocumentDecryptorTest {

	public static final String MASTER_KEY_ARN = "arn:aws:kms:us-east-1:073204089135:key/b4985799-964b-4383-8b91-9d82d866858d";
	public static final String AWS_ENDPOINT = "https://kms.us-east-1.amazonaws.com";

	@Test
	// @org.junit.Ignore
	public void testDecryptDocumentStringString() throws Exception {

		SecretKeyInfoFactory skif = new SecretKeyInfoFactory(MASTER_KEY_ARN,
				DEFAULT_AWS_KEY_ENCRYPTION_ALGORITHM, AWS_ENDPOINT);
		EncryptedKeyFactory ekf = new EncryptedKeyFactory();
		final DocumentEncryptor encryptor = new DocumentEncryptor(skif, ekf);
		final DocumentDecryptor decryptor = new DocumentDecryptor(AWS_ENDPOINT);

		for (String plaintext : TestData.getTestData()) {

			InputStream sourceDocument = this.getClass().getClassLoader()
					.getResourceAsStream(plaintext);
			DocumentBuilder builder = XMLUtils.createDocumentBuilder(false);
			final Document original = builder.parse(sourceDocument);
			final Element originalRoot = original.getDocumentElement();

			// Get the tag names of the elements that are immediate children
			// of the root.
			// Element root = decrypted.getDocumentElement();
			Set<String> tagNamesClearText = new LinkedHashSet<>();
			// NodeList nl = root.getChildNodes();
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

			encryptor.encrypt(original);

			Document decrypted = builder.newDocument();
			Node copiedRoot = decrypted.importNode(originalRoot, true);
			decrypted.appendChild(copiedRoot);

			// Before decryption, the immediate children of the root should be
			// exactly one EncryptedData element.
			Set<String> tagNamesEncrypted = new LinkedHashSet<>();
			nl = decrypted.getDocumentElement().getChildNodes();
			for (String tagName : tagNamesEncrypted) {
				nl = decrypted.getElementsByTagName(tagName);
				assertTrue(nl.getLength() == 1);
			}
			assertTrue(nl.getLength() == 1);
			Node n = nl.item(0);
			assertTrue(n instanceof Element);
			Element e = (Element) n;
			assertTrue("xenc:EncryptedData".equals(e.getTagName()));

			decryptor.decrypt(decrypted);

			// After decryption, there should be least one immediate child of
			// the
			// root element for every document in the test data.
			for (String tagName : tagNamesClearText) {
				nl = decrypted.getElementsByTagName(tagName);
				assertTrue(nl.getLength() > 0);
			}
			// After decryption, there should be no EncryptedData elements
			nl = decrypted.getElementsByTagName("xenc:EncryptedData");
			assertTrue(nl.getLength() == 0);

		}

	}

}
