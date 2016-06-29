package com.choicemaker.xmlencryption;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

import javax.crypto.SecretKey;

import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.utils.EncryptionConstants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import com.amazonaws.auth.AWSCredentials;
import com.choicemaker.utilcopy01.KeyUtils;
import com.choicemaker.utilcopy01.Precondition;
import com.choicemaker.utilcopy01.SystemPropertyUtils;
import com.choicemaker.utilcopy01.WSS4JConstants;

public class DocumentDecryptor {

	private static final Logger logger = Logger
			.getLogger(DocumentDecryptor.class.getName());

	private static final String KEYNAME_LN = "KeyName";
	private static final String CIPHERDATA_LN = "CipherData";
	private static final String CIPHERVALUE_LN = "CipherValue";

	static {
		// Security.addProvider(new
		// org.bouncycastle.jce.provider.BouncyCastleProvider());
		org.apache.xml.security.Init.init();
	}

	public static void decryptElement(Document doc, Element elementToDecrypt,
			String encAlgoRootContent, SecretKey secretKey) throws Exception {
		XMLCipher xmlCipher = XMLCipher.getInstance(encAlgoRootContent);
		xmlCipher.init(XMLCipher.DECRYPT_MODE, secretKey);
		final boolean content = true;

		logger.fine("Before decryption: "
				+ SystemPropertyUtils.PV_LINE_SEPARATOR
				+ XMLPrettyPrint.print(elementToDecrypt));
		xmlCipher.doFinal(doc, elementToDecrypt, content);
		logger.fine("After decryption: "
				+ SystemPropertyUtils.PV_LINE_SEPARATOR
				+ XMLPrettyPrint.print(elementToDecrypt));
	}

	private static String determineEncryptionMethod(Element e) {
		Element ek = findSingleChildElementByTagNameNS(e,
				EncryptionConstants.EncryptionSpecNS, WSS4JConstants.ENC_PREFIX
						+ ":" + EncryptionConstants._TAG_ENCRYPTIONMETHOD);
		String retVal = ek.getAttributeNS(null,
				EncryptionConstants._ATT_ALGORITHM);
		if (retVal == null || retVal.trim().isEmpty()) {
			String msg = "Missing algorithm attribute";
			throw new IllegalArgumentException(msg);
		}
		return retVal;
	}

	private static String determineMasterKeyId(Element e) {
		Element ki = findSingleChildElementByTagNameNS(e,
				WSS4JConstants.SIG_NS, WSS4JConstants.SIG_PREFIX + ":"
						+ WSS4JConstants.KEYINFO_LN);
		Element kn = findSingleChildElementByTagNameNS(ki,
				WSS4JConstants.SIG_NS, WSS4JConstants.SIG_PREFIX + ":"
						+ KEYNAME_LN);
		String retVal = kn.getTextContent();
		return retVal;
	}

	private static Element findEncryptedContent(Element e) {
		Element retVal = findSingleChildElementByTagNameNS(e,
				EncryptionConstants.EncryptionSpecNS, WSS4JConstants.ENC_PREFIX
						+ ":" + EncryptionConstants._TAG_ENCRYPTEDDATA);
		return retVal;
	}

	protected static Element findSingleChildElementByTagNameNS(Element e,
			String namespaceURI, String localName) {
		Precondition.assertNonNullArgument("null element", e);
		Precondition
				.assertNonEmptyString("null or blank local name", localName);

		// NodeList nl = e.getElementsByTagNameNS(namespaceURI, localName);
		NodeList nl = e.getChildNodes();
		assert nl != null;
		List<Element> el = new ArrayList<>();
		final int nlCount = nl.getLength();
		for (int i = 0; i < nlCount; i++) {
			Node n = nl.item(i);
			if (n instanceof Element) {
				Element ce = (Element) n;
				if (namespaceURI != null
						&& !namespaceURI.equals(ce.getNamespaceURI())) {
					continue;
				}
				if (!localName.equals(ce.getTagName())) {
					continue;
				}
				el.add(ce);
			}
		}
		final int elCount = el.size();
		if (elCount != 1) {
			String msg = "Invalid number of '" + localName + "' elements: "
					+ elCount;
			throw new IllegalArgumentException(msg);
		}
		Element retVal = el.get(0);
		return retVal;
	}

	private static String getCipherValue(Element e) {
		Element cd = findSingleChildElementByTagNameNS(e,
				WSS4JConstants.ENC_NS, WSS4JConstants.ENC_PREFIX + ":"
						+ CIPHERDATA_LN);
		Element cv = findSingleChildElementByTagNameNS(cd,
				WSS4JConstants.ENC_NS, WSS4JConstants.ENC_PREFIX + ":"
						+ CIPHERVALUE_LN);
		String retVal = cv.getTextContent();
		return retVal;
	}

	private static Element getDocumentElement(Document doc) {
		Element retVal = doc.getDocumentElement();
		if (retVal == null) {
			String msg = "Document element is not set";
			throw new IllegalArgumentException(msg);
		}
		assert retVal != null;
		return retVal;
	}

	private final String endpoint;

	private final AWSCredentials creds;

	public DocumentDecryptor(EncryptionScheme es, CredentialSet ec) {
		Precondition.assertNonNullArgument("null scheme", es);
		Precondition.assertNonNullArgument("null credentials", es);
		if (!(es instanceof AwsKmsEncryptionScheme)) {
			throw new Error("not yet implemented");
		}
		AwsKmsEncryptionScheme awsScheme = (AwsKmsEncryptionScheme) es;
		this.endpoint = awsScheme.getEndpoint(ec);
		this.creds = awsScheme.getAwsKmsCredentials(ec);
	}

	public void decrypt(final Document doc) throws Exception {
		Precondition.assertNonNullArgument("null document", doc);

		// Get encryption components for the root content
		final Element root = getDocumentElement(doc);
		final Element edRootContent = findEncryptedContent(root);
		final String encAlgoRootContent = determineEncryptionMethod(edRootContent);
		final Element ekRootContent = findEncryptedKey(edRootContent);

		// Get the encryption components for the secret key
		final String encAlgoSecretKey = determineEncryptionMethod(ekRootContent);
		final String masterKeyId = determineMasterKeyId(ekRootContent);
		final String encValueSecretKey = getCipherValue(ekRootContent);
		final ByteBuffer encBuffer = AwsKmsUtils.computeSecretBytes(creds,
				masterKeyId, encAlgoSecretKey, encValueSecretKey, endpoint);
		final byte[] encBytes = new byte[encBuffer.remaining()];
		encBuffer.get(encBytes);
		final SecretKey secretKey = KeyUtils.prepareSecretKey(
				encAlgoRootContent, encBytes);

		// Decrypt the content of the root element
		decryptElement(doc, root, encAlgoRootContent, secretKey);
	}

	private Element findEncryptedKey(Element e) {
		Element ki = findSingleChildElementByTagNameNS(e,
				WSS4JConstants.SIG_NS, WSS4JConstants.SIG_PREFIX + ":"
						+ WSS4JConstants.KEYINFO_LN);
		Element retVal = findSingleChildElementByTagNameNS(ki,
				WSS4JConstants.ENC_NS, WSS4JConstants.ENC_PREFIX + ":"
						+ WSS4JConstants.ENC_KEY_LN);
		return retVal;
	}

}
