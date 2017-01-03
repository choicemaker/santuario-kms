package com.choicemaker.xmlencryption;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;

import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import com.choicemaker.utilcopy01.SystemPropertyUtils;

public class TestUtils {
	
	private TestUtils() {
	}

	static final String EOL = SystemPropertyUtils.PV_LINE_SEPARATOR;

	static SecretKeyInfoFactory createSKIFactory(
			AwsKmsCredentialSet encCredentials,
			AwsKmsEncryptionScheme encScheme) throws IOException {
		// Create the SecretKey that will encrypt the document
		SecretKeyInfoFactory retVal = encScheme.getSecretKeyInfoFactory(
				encCredentials, encScheme.getKeyEncryptionAlgorithm(),
				Collections.emptyMap());
		return retVal;
	}

	static AwsKmsCredentialSet getCredentialSet() throws IOException {
		String credentialName = "alice";
		AwsKmsCredentialSet retVal = new AwsKmsCredentialSet(credentialName);
		return retVal;
	}

	static AwsKmsEncryptionScheme getEncryptionScheme() {
		AwsKmsEncryptionScheme retVal = new AwsKmsEncryptionScheme();
		return retVal;
	}

	static boolean checkNodeCount(String resourceName, QName root,
			int expectedCount) {
		InputStream is =
				TestUtils.class.getClassLoader().getResourceAsStream(resourceName);
		return checkNodeCount(is, root, expectedCount);
	}

	static boolean checkNodeCount(byte[] bytes, QName root,
			int expectedCount) {
		InputStream is = new ByteArrayInputStream(bytes);
		return checkNodeCount(is, root, expectedCount);
	}

	static boolean checkNodeCount(InputStream is, QName root,
			int expectedCount) {
		boolean retVal = false;
		if (is != null) {
			try {
				final DocumentBuilder documentBuilder =
					XMLUtils.createDocumentBuilder(false);
				Document doc = documentBuilder.parse(is);
				retVal = checkNodeCount(doc, root, expectedCount);
			} catch (Exception x) {
				assert retVal == false;
			}
		}
		return retVal;
	}

	static boolean checkNodeCount(Document doc, QName root,
			int expectedCount) {
		String nsURI = root.getNamespaceURI();
		String lname = root.getLocalPart();
		NodeList nodes = doc.getElementsByTagNameNS(nsURI, lname);
		boolean retVal = nodes.getLength() == expectedCount;
		return retVal;
	}

}
