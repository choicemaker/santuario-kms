package com.choicemaker.xmlencryption;

import java.util.Collections;
import java.util.logging.Logger;

import javax.crypto.SecretKey;

import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.stax.impl.util.IDGenerator;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import com.choicemaker.utilcopy01.KeyUtils;
import com.choicemaker.utilcopy01.Precondition;
import com.choicemaker.utilcopy01.SystemPropertyUtils;
import com.choicemaker.utilcopy01.WSS4JConstants;

public class DocumentEncryptor {

	private static final Logger logger = Logger
			.getLogger(DocumentEncryptor.class.getName());

	static {
		// Security.addProvider(new
		// org.bouncycastle.jce.provider.BouncyCastleProvider());
		org.apache.xml.security.Init.init();
	}

	private static void encryptElement(Document doc, Element elementToEncrypt,
			String docEncAlgo, SecretKey secretKey, KeyInfo keyInfo)
			throws Exception {
		final XMLCipher xmlCipher = XMLCipher.getInstance(docEncAlgo);
		xmlCipher.init(XMLCipher.ENCRYPT_MODE, secretKey);
		EncryptedData encData = xmlCipher.getEncryptedData();
		final String xencEncryptedDataId = generateEncryptedDataId();
		encData.setId(xencEncryptedDataId);
		encData.setKeyInfo(keyInfo);
		final boolean content = true;
		logger.fine("Before encryption: "
				+ SystemPropertyUtils.PV_LINE_SEPARATOR
				+ XMLPrettyPrint.print(elementToEncrypt));
		xmlCipher.doFinal(doc, elementToEncrypt, content);
		logger.fine("After encryption: "
				+ SystemPropertyUtils.PV_LINE_SEPARATOR
				+ XMLPrettyPrint.print(elementToEncrypt));
	}

	private static String generateEncryptedDataId() {
		String retVal = IDGenerator.generateID("ED-");
		return retVal;
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

	private final CredentialSet credential;
	private final EncryptionScheme scheme;
	private final SecretKeyInfoFactory skiFactory;
	private final EncryptedKeyFactory ekFactory = new EncryptedKeyFactory();

	public DocumentEncryptor(EncryptionScheme es, CredentialSet cs) {
		Precondition.assertNonNullArgument("null credentials", cs);
		Precondition.assertNonNullArgument("null scheme", es);

		credential = cs;
		scheme = es;
		skiFactory = es.getSecretKeyInfoFactory(cs,
				es.getKeyEncryptionAlgorithm(), Collections.emptyMap());
	}

	public CredentialSet getCredential() {
		return credential;
	}

	public EncryptionScheme getScheme() {
		return scheme;
	}

	private KeyInfo createKeyInfo(Document document, Element encKey) {

		KeyInfo keyInfo = new KeyInfo(document);
		keyInfo.addUnknownElement(encKey);
		Element keyInfoElement = keyInfo.getElement();
		keyInfoElement.setAttributeNS(WSS4JConstants.XMLNS_NS, "xmlns:"
				+ WSS4JConstants.SIG_PREFIX, WSS4JConstants.SIG_NS);

		return keyInfo;
	}

	public void encrypt(Document doc) throws Exception {
		encrypt(doc, DefaultAlgorithms.DEFAULT_KEY_ENCRYPT_ALGO,
				DefaultAlgorithms.DEFAULT_DOC_ENCRYPT_ALGORITHM);
	}

	/**
	 * Encrypts the content of the root element of an XML document.
	 * 
	 * @param doc
	 *            the document to be encrypted. The content of the root element
	 *            will be replaced with EncryptedData.
	 * @param keyEncAlgo
	 *            the key encryption algorithm; see
	 *            {@link DefaultAlgorithms#DEFAULT_KEY_ENCRYPT_ALGO} for the
	 *            recommended algorithm.
	 * @param docEncAlgo
	 *            the name of the currently selected symmetric document
	 *            encryption algorithm; see {@link WSConstants#TRIPLE_DES
	 *            TRIPLE_DES}, {@link WSConstants#AES_128 AES_128},
	 *            {@link WSConstants#AES_192 AES_192}, or
	 *            {@link WSConstants#AES_256 AES_256}.
	 * @throws Exception
	 */
	public void encrypt(final Document doc, String keyEncAlgo, String docEncAlgo)
			throws Exception {

		// Preconditions
		Precondition.assertNonNullArgument("null document", doc);
		Precondition.assertNonEmptyString(
				"null or blank key encryption algorithm", keyEncAlgo);
		Precondition.assertNonEmptyString(
				"null or blank document encryption algorithm", docEncAlgo);

		// Find the document's root element and construct an XMLCipher instance
		final Element root = getDocumentElement(doc);

		// Create the SecretKey that will encrypt the document
		SecretKeyInfo ski = skiFactory.createSessionKey();
		final SecretKey secretKey = KeyUtils.prepareSecretKey(docEncAlgo,
				ski.getKey());

		// Create the encrypted key element that will replace the root content
		Element ek = ekFactory.createEncryptedKeyElement(doc, keyEncAlgo, ski);
		final KeyInfo keyInfo = createKeyInfo(doc, ek);

		// Encrypt the content of the root element
		encryptElement(doc, root, docEncAlgo, secretKey, keyInfo);
	}

}
