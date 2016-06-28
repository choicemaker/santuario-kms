package com.choicemaker.xmlencryption;

import static com.choicemaker.xmlencryption.AwsKmsUtils.DEFAULT_AWS_KEY_ENCRYPTION_ALGORITHM;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.InputStream;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.logging.Logger;

import javax.xml.parsers.DocumentBuilder;

import org.apache.xml.security.utils.XMLUtils;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xmlunit.builder.DiffBuilder;
import org.xmlunit.diff.Diff;
import org.xmlunit.diff.Difference;

public class DocumentEncryptorDecryptorTest {

	private static final Logger logger = Logger
			.getLogger(DocumentEncryptorDecryptorTest.class.getName());

	public static final String MASTER_KEY_ARN = "arn:aws:kms:us-east-1:073204089135:key/b4985799-964b-4383-8b91-9d82d866858d";
	public static final String AWS_ENDPOINT = "https://kms.us-east-1.amazonaws.com";

	public static final int BUFFER_SIZE = 1000;

	@Test
	public void testEncryptDecryptDocument() throws Exception {

		SecretKeyInfoFactory skif = new AwsKmsSecretKeyInfoFactory(MASTER_KEY_ARN,
				DEFAULT_AWS_KEY_ENCRYPTION_ALGORITHM, AWS_ENDPOINT);
		final DocumentEncryptor encryptor = new DocumentEncryptor(skif);
		final DocumentDecryptor decryptor = new DocumentDecryptor(AWS_ENDPOINT);

		for (String plaintext : TestData.getTestData()) {

			InputStream sourceDocument = this.getClass().getClassLoader()
					.getResourceAsStream(plaintext);
			DocumentBuilder builder = XMLUtils.createDocumentBuilder(false);
			final Document original = builder.parse(sourceDocument);
			final Element originalRoot = original.getDocumentElement();
			final String originalAsString = XMLPrettyPrint.print(original);
			logger.info("original: " + originalAsString);

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
			logger.info("decrypted: " + XMLPrettyPrint.print(decrypted));

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
					.checkForSimilar().build();
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
