package com.choicemaker.xmlencryption;

import java.util.logging.Logger;

import org.apache.xml.security.stax.impl.util.IDGenerator;
import org.apache.xml.security.utils.Base64;
import org.apache.xml.security.utils.EncryptionConstants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Text;

import com.choicemaker.utilcopy01.SystemPropertyUtils;
import com.choicemaker.utilcopy01.WSS4JConstants;
import com.choicemaker.utilcopy01.XMLUtils;

public class EncryptedKeyFactory {

	private static final Logger logger = Logger
			.getLogger(EncryptedKeyFactory.class.getName());

	public static final String DEFAULT_KEY_ENCRYPT_ALGO = "http://www.w3.org/2001/04/xmlenc#kw-aes256";

	protected Text createBase64EncodedTextNode(Document doc, byte[] data) {
		return doc.createTextNode(Base64.encode(data));
	}

	protected Element createCipherValue(Document doc, Element encryptedKey) {
		Element cipherData = doc.createElementNS(WSS4JConstants.ENC_NS,
				WSS4JConstants.ENC_PREFIX + ":CipherData");
		Element cipherValue = doc.createElementNS(WSS4JConstants.ENC_NS,
				WSS4JConstants.ENC_PREFIX + ":CipherValue");
		cipherData.appendChild(cipherValue);
		encryptedKey.appendChild(cipherData);
		return cipherValue;
	}

	protected Element createEncryptedKey(Document doc, String keyTransportAlgo) {
		Element encryptedKey = doc.createElementNS(WSS4JConstants.ENC_NS,
				WSS4JConstants.ENC_PREFIX + ":EncryptedKey");

		XMLUtils.setNamespace(encryptedKey, WSS4JConstants.ENC_NS,
				WSS4JConstants.ENC_PREFIX);
		Element encryptionMethod = doc.createElementNS(WSS4JConstants.ENC_NS,
				WSS4JConstants.ENC_PREFIX + ":EncryptionMethod");
		encryptionMethod.setAttributeNS(null,
				EncryptionConstants._ATT_ALGORITHM, keyTransportAlgo);
		encryptedKey.appendChild(encryptionMethod);
		return encryptedKey;
	}

	public Element createEncryptedKeyElement(Document document,
			SecretKeyInfo ski) {
		Element retVal = createEncryptedKeyElement(document,
				DEFAULT_KEY_ENCRYPT_ALGO, ski);
		return retVal;
	}

	public Element createEncryptedKeyElement(Document document,
			String keyEncAlgo, SecretKeyInfo ski) {
		Element retVal = createEncryptedKey(document, keyEncAlgo);
		String encKeyId = IDGenerator.generateID("EK-");
		retVal.setAttributeNS(null, "Id", encKeyId);
		retVal.appendChild(document.adoptNode(ski.getKeyInfoReference()));
		Element cipherValue = createCipherValue(document, retVal);
		Text keyText = createBase64EncodedTextNode(document,
				ski.getEncryptedSecret());
		cipherValue.appendChild(keyText);
		logger.fine("EncryptedKey: " + SystemPropertyUtils.PV_LINE_SEPARATOR
				+ XMLPrettyPrint.print(retVal));
		return retVal;
	}

}
