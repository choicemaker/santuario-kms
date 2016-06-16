package com.choicemaker.xmlencryption;

import java.security.Security;
import java.util.logging.Logger;

import javax.crypto.SecretKey;

import org.apache.wss4j.common.util.KeyUtils;
import org.apache.wss4j.dom.WSConstants;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.encryption.XMLEncryptionException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.stax.impl.util.IDGenerator;
import org.apache.xml.security.utils.EncryptionConstants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import com.choicemaker.util.Precondition;
import com.choicemaker.util.SystemPropertyUtils;
import com.choicemaker.xmlencryption.SecretKeyInfoFactory.SecretKeyInfo;

public class DocumentDecryptor {

	private static final Logger logger = Logger
			.getLogger(DocumentDecryptor.class.getName());

	static {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		org.apache.xml.security.Init.init();
	}

	private static Element getDocumentElement(Document doc) {
		Element retVal = doc.getDocumentElement();
		if (retVal == null) {
			NodeList nl = doc.getChildNodes();
			assert nl != null;
			final int countDocChildNodes = nl == null ? 0 : nl.getLength();
			if (countDocChildNodes == 0) {
				String msg = "Document has no nodes";
				throw new IllegalArgumentException(msg);
			}
			if (countDocChildNodes > 1) {
				String msg = "Document has multiple child nodes: "
						+ countDocChildNodes;
				throw new IllegalArgumentException(msg);
			}
			Node n = nl.item(0);
			if (!(n instanceof Element)) {
				String msg = "Child node of document is not an element: '"
						+ n.getClass().getName() + "'";
				throw new IllegalArgumentException(msg);
			}
			retVal = (Element) n;
		}
		assert retVal != null;
		return retVal;
	}

	public void decrypt(final Document doc) throws Exception {
		Precondition.assertNonNullArgument("null document", doc);
		
		// Get encryption components for the root content
		final Element root = getDocumentElement(doc);
		final Element edRootContent = findEncryptedContent(root);
		final String encAlgoRootContent = determineEncryptionMethod(edRootContent);
		final Element ekRootContent = findEncryptedKey(edRootContent);
//		final String encValueRootContent = getCipherValue(edRootContent);
		
		// Get the encryption components for the secret key
		final String encAlgoSecretKey = determineEncryptionMethod(ekRootContent);
		final String masterKeyId = determineMasterKeyId(ekRootContent);
		final String encValueSecretKey = getCipherValue(ekRootContent);
		final SecretKey secretKey = computeSecretKey(masterKeyId, encAlgoSecretKey, encValueSecretKey);
		
		// Decrypt the content of the root element
		decryptElement(doc, root, encAlgoRootContent, secretKey);
	}

	private static void decryptElement(Document doc, Element elementToDecrypt,
			String encAlgoRootContent, SecretKey secretKey) throws Exception {
		XMLCipher xmlCipher = XMLCipher.getInstance(encAlgoRootContent);
        xmlCipher.init(XMLCipher.DECRYPT_MODE, secretKey);
        xmlCipher.doFinal(doc, elementToDecrypt);
	}

	private static SecretKey computeSecretKey(String masterKeyId,
			String encAlgoSecretKey, String encValueSecretKey) {
		// TODO Auto-generated method stub
		return null;
	}

	private static String determineMasterKeyId(Element ekRootContent) {
		// TODO Auto-generated method stub
		return null;
	}

	private static String getCipherValue(Element edRootContent) {
		// TODO Auto-generated method stub
		return null;
	}

	private Element findEncryptedKey(Element e) {
		// TODO Auto-generated method stub
		return null;
	}

	private static String determineEncryptionMethod(Element e) {
		Precondition.assertNonNullArgument("Null element", e);
		NodeList nl =
                e.getElementsByTagNameNS(
                    EncryptionConstants.EncryptionSpecNS,
                    EncryptionConstants._TAG_ENCRYPTIONMETHOD);
		assert nl != null;
		if (nl.getLength() != 1) {
			String msg = "Invalid number of EncryptionMethod elements: " + nl.getLength();
			throw new IllegalArgumentException(msg);
		}
		Element ek = (Element) nl.item(0);
		String retVal = ek.getAttributeNS(null, "Algorithm");
		if (retVal == null || retVal.trim().isEmpty()) {
			String msg = "Missing algorithm attribute";
			throw new IllegalArgumentException(msg);
		}
		return retVal;
	}

	private static Element findEncryptedContent(Element e) {
		Precondition.assertNonNullArgument("Null element", e);
		NodeList nl =
                e.getElementsByTagNameNS(
                    EncryptionConstants.EncryptionSpecNS,
                    EncryptionConstants._TAG_ENCRYPTEDDATA);
		assert nl != null;
		if (nl.getLength() != 1) {
			String msg = "Invalid number of EncryptedData elements: " + nl.getLength();
			throw new IllegalArgumentException(msg);
		}
		Element retVal = (Element) nl.item(0);
		assert retVal != null;
		return retVal;
	}

}
