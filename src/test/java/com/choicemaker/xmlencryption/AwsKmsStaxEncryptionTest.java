/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package com.choicemaker.xmlencryption;

import static com.choicemaker.xmlencryption.TestUtils.checkNodeCount;
import static com.choicemaker.xmlencryption.TestUtils.getCredentialSet;
import static com.choicemaker.xmlencryption.TestUtils.getEcryptionScheme;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.config.JCEAlgorithmMapper;
import org.apache.xml.security.stax.ext.OutboundXMLSec;
import org.apache.xml.security.stax.ext.OutputProcessor;
import org.apache.xml.security.stax.ext.SecurePart;
import org.apache.xml.security.stax.ext.XMLSec;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.stax.impl.DocumentContextImpl;
import org.apache.xml.security.stax.impl.OutboundSecurityContextImpl;
import org.apache.xml.security.stax.impl.OutputProcessorChainImpl;
import org.apache.xml.security.stax.impl.XMLSecurityStreamWriter;
import org.apache.xml.security.stax.impl.processor.output.FinalOutputProcessor;
import org.apache.xml.security.stax.impl.processor.output.XMLEncryptOutputProcessor;
import org.apache.xml.security.stax.impl.processor.output.XMLSignatureOutputProcessor;
import org.apache.xml.security.stax.impl.securityToken.GenericOutboundSecurityToken;
import org.apache.xml.security.stax.impl.util.IDGenerator;
import org.apache.xml.security.stax.securityToken.OutboundSecurityToken;
import org.apache.xml.security.stax.securityToken.SecurityTokenConstants;
import org.apache.xml.security.stax.securityToken.SecurityTokenProvider;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.Assert;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import com.choicemaker.utilcopy01.KeyUtils;

/**
 * Encrypts an entire document via StAX, but encryption fails for some documents
 * because the document root is left as plain text
 */
public class AwsKmsStaxEncryptionTest extends org.junit.Assert {

	static {
		org.apache.xml.security.Init.init();
	}

	// Encrypt and check various documents using StAX
	@org.junit.Test
	public void testStAXEncryption() throws Exception {

		List<String> errors = new ArrayList<>();
		for (Object[] td : TestData.getTestData()) {

			// Check the test data
			Assert.assertTrue(td != null && td.length == 2);
			final String docName = (String) td[0];
			final QName docRoot = (QName) td[1];
			Assert.assertTrue(checkNodeCount(docName, docRoot, 1));

			try {
				testStAXEncryption(docName, null);
			} catch (Throwable x) {
				String msg =
					"Failed to encrypt implicit root '" + docRoot.getLocalPart()
							+ "' in '" + docName + "' with wrapping key";
				msg += ": " + x.toString();
				errors.add(msg);
			}
		}
		if (errors.size() > 0) {
			final String INDENT = "   ";
			StringBuilder sb = new StringBuilder();
			sb.append("Errors: ").append(errors.size()).append(TestUtils.EOL);
			for (String error : errors) {
				sb.append(INDENT).append(error).append(TestUtils.EOL);
			}
			String msg = sb.toString();
			fail(msg);
		}
	}

	// Encrypt using StAX and check the root
	public void testStAXEncryption(String docName, QName root)
			throws Exception {

		// Read in cleartext document
		InputStream clearSource =
			this.getClass().getClassLoader().getResourceAsStream(docName);
		Assert.assertTrue("null cleartext input stream", clearSource != null);
		final DocumentBuilder documentBuilder =
			XMLUtils.createDocumentBuilder(false);
		final Document clearDoc = documentBuilder.parse(clearSource);
		XMLUtils.outputDOM(clearDoc, System.out);

		// Check that the root is present
		final Element clearRoot = clearDoc.getDocumentElement();
		final String clearRootNS = clearRoot.getNamespaceURI();
		final String clearRootLN = clearRoot.getLocalName();
		NodeList clearNodes =
			clearDoc.getElementsByTagNameNS(clearRootNS, clearRootLN);
		Assert.assertEquals("missing computed root ?!?", clearNodes.getLength(),
				1);
		if (root != null) {
			final String ns = root.getNamespaceURI();
			final String ln = root.getLocalPart();
			clearNodes = clearDoc.getElementsByTagNameNS(ns, ln);
			Assert.assertEquals("missing specified root",
					clearNodes.getLength(), 1);
			if (!clearRootNS.equals(ns)) {
				String msg = "WARNING: computed namespace '" + clearRootNS
						+ "' doesn't match specified namespace '" + ns + "'";
				System.err.println(msg);
			}
			if (!clearRootLN.equals(ln)) {
				String msg = "WARNING: computed root name '" + clearRootLN
						+ "' doesn't match specified root name '" + ln + "'";
				System.err.println(msg);
			}
		}

		// Encrypt entire document using StAX
		clearSource.close();
		clearSource =
			this.getClass().getClassLoader().getResourceAsStream(docName);
		final ByteArrayOutputStream baos =
			encryptEntireDocUsingStAX(clearSource);

		// Load the encrypted document from the output stream
		InputStream encryptedSource =
			new ByteArrayInputStream(baos.toByteArray());
		Document encryptedDoc = documentBuilder.parse(encryptedSource);
		XMLUtils.outputDOM(encryptedDoc, System.out);

		// Check that the root is not encrypted
		NodeList encryptedNodes =
			encryptedDoc.getElementsByTagNameNS(clearRootNS, clearRootLN);
		Assert.assertEquals("unencrypted root", encryptedNodes.getLength(), 1);

		// Check that the root has exactly one child that is encrypted
		Element r = (Element) encryptedNodes.item(0);
		NodeList clist = r.getChildNodes();
		Assert.assertEquals("more than one child node", clist.getLength(), 1);
		Element c = (Element) clist.item(0);
		String cln = c.getLocalName();
		Assert.assertEquals("content not encrypted", cln, "EncryptedData");
	}

	/**
	 * Encrypt the entire document using the StAX API of Apache Santuario - XML
	 * Security for Java. If a wrappingKey is supplied, this is used to encrypt
	 * the encryptingKey + place it in an EncryptedKey structure.
	 */
	public static ByteArrayOutputStream encryptEntireDocUsingStAX(
			InputStream inputStream) throws Exception {

		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		XMLStreamWriter xmlStreamWriter =
			createXMLSecureStreamWriter(baos, "UTF-8");

		XMLInputFactory xmlInputFactory = XMLInputFactory.newInstance();
		XMLStreamReader xmlStreamReader =
			xmlInputFactory.createXMLStreamReader(inputStream);

		XMLBorrowedUtils.writeAll(xmlStreamReader, xmlStreamWriter);
		xmlStreamWriter.close();

		return baos;
	}

	static XMLStreamWriter createXMLSecureStreamWriter(
			ByteArrayOutputStream baos, String string)
			throws XMLSecurityException, IOException {

		// Set up the AWS KMS configuration
		final AwsKmsEncryptionScheme es = getEcryptionScheme();
		final AwsKmsCredentialSet cs = getCredentialSet();
		final SecretKeyInfoFactory skiFactory = es.getSecretKeyInfoFactory(cs,
				es.getKeyEncryptionAlgorithm(), Collections.emptyMap());
		final SecretKeyInfo ski = skiFactory.createSessionKey();
		final String docEncAlgo = DefaultAlgorithms.DEFAULT_DOC_ENCRYPT_ALGO;
		final SecretKey encryptingKey =
			KeyUtils.prepareSecretKey(docEncAlgo, ski.getKey());

		// Set up the StAX configuration
		final XMLSecurityProperties properties = new XMLSecurityProperties();
		properties.setEncryptionSymAlgorithm(docEncAlgo);
		properties.setEncryptionKey(encryptingKey);
		properties.setEncryptionKeyIdentifier(
				SecurityTokenConstants.KeyIdentifier_X509KeyIdentifier);
		// final String keyEncAlgo = DefaultAlgorithms.DECLARED_KEY_ENCRYPTION;
		// if (wrappingKey != null) {
		// properties.setEncryptionKeyTransportAlgorithm(
		// "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p");
		// properties.setEncryptionTransportKey(wrappingKey);
		// }
		// properties.setEncryptionKeyIdentifier(
		// SecurityTokenConstants.KeyIdentifier_EncryptedKey);

		List<XMLSecurityConstants.Action> actions =
			new ArrayList<XMLSecurityConstants.Action>();
		actions.add(XMLSecurityConstants.ENCRYPT);
		properties.setActions(actions);

		// final SecurePart.Modifier modifier = SecurePart.Modifier.Element;
		final SecurePart.Modifier modifier = SecurePart.Modifier.Content;
		final String externalReference = "";
		final SecurePart securePart =
			new SecurePart(externalReference, modifier);
		securePart.setSecureEntireRequest(true);
		securePart.setRequired(true);
		properties.addEncryptionPart(securePart);

		// final OutboundXMLSec outboundXMLSec =
		// XMLSec.getOutboundXMLSec(properties);
		// XMLStreamWriter xmlStreamWriter =
		// outboundXMLSec.processOutMessage(baos, "UTF-8");

		XMLSecurityProperties securityProperties =
			XMLSec.validateAndApplyDefaultsToOutboundSecurityProperties(
					properties);
		XMLStreamWriter xmlStreamWriter =
			processOutMessage(baos, "UTF-8", securityProperties);
		return xmlStreamWriter;
	}

	static XMLStreamWriter processOutMessage(Object output, String encoding,
			XMLSecurityProperties securityProperties)
			throws XMLSecurityException {
		final OutboundSecurityContextImpl outboundSecurityContext =
			new OutboundSecurityContextImpl();
		final DocumentContextImpl documentContext = new DocumentContextImpl();
		documentContext.setEncoding(encoding);

		OutputProcessorChainImpl outputProcessorChain =
			new OutputProcessorChainImpl(outboundSecurityContext,
					documentContext);

		SecurePart signEntireRequestPart = null;
		SecurePart encryptEntireRequestPart = null;

		for (XMLSecurityConstants.Action action : securityProperties
				.getActions()) {
			if (XMLSecurityConstants.SIGNATURE.equals(action)) {
				XMLSignatureOutputProcessor signatureOutputProcessor =
					new XMLSignatureOutputProcessor();
				initializeOutputProcessor(outputProcessorChain,
						signatureOutputProcessor, action, securityProperties);

				configureSignatureKeys(outboundSecurityContext,
						securityProperties);
				List<SecurePart> signatureParts =
					securityProperties.getSignatureSecureParts();
				for (int j = 0; j < signatureParts.size(); j++) {
					SecurePart securePart = signatureParts.get(j);
					if (securePart.getIdToSign() == null
							&& securePart.getName() != null) {
						outputProcessorChain.getSecurityContext().putAsMap(
								XMLSecurityConstants.SIGNATURE_PARTS,
								securePart.getName(), securePart);
					} else if (securePart.getIdToSign() != null) {
						outputProcessorChain.getSecurityContext().putAsMap(
								XMLSecurityConstants.SIGNATURE_PARTS,
								securePart.getIdToSign(), securePart);
					} else if (securePart.isSecureEntireRequest()) {
						// Special functionality to sign the first element in
						// the request
						signEntireRequestPart = securePart;
					}
				}
			} else if (XMLSecurityConstants.ENCRYPT.equals(action)) {
				XMLEncryptOutputProcessor encryptOutputProcessor =
					new XMLEncryptOutputProcessor();
				initializeOutputProcessor(outputProcessorChain,
						encryptOutputProcessor, action, securityProperties);

				configureEncryptionKeys(outboundSecurityContext,
						securityProperties);
				List<SecurePart> encryptionParts =
					securityProperties.getEncryptionSecureParts();
				for (int j = 0; j < encryptionParts.size(); j++) {
					SecurePart securePart = encryptionParts.get(j);
					if (securePart.getIdToSign() == null
							&& securePart.getName() != null) {
						outputProcessorChain.getSecurityContext().putAsMap(
								XMLSecurityConstants.ENCRYPTION_PARTS,
								securePart.getName(), securePart);
					} else if (securePart.getIdToSign() != null) {
						outputProcessorChain.getSecurityContext().putAsMap(
								XMLSecurityConstants.ENCRYPTION_PARTS,
								securePart.getIdToSign(), securePart);
					} else if (securePart.isSecureEntireRequest()) {
						// Special functionality to encrypt the first element in
						// the request
						encryptEntireRequestPart = securePart;
					}
				}
			}
		}
		if (output instanceof OutputStream) {
			final FinalOutputProcessor finalOutputProcessor =
				new FinalOutputProcessor((OutputStream) output, encoding);
			initializeOutputProcessor(outputProcessorChain,
					finalOutputProcessor, null, securityProperties);

		} else if (output instanceof XMLStreamWriter) {
			final FinalOutputProcessor finalOutputProcessor =
				new FinalOutputProcessor((XMLStreamWriter) output);
			initializeOutputProcessor(outputProcessorChain,
					finalOutputProcessor, null, securityProperties);

		} else {
			throw new IllegalArgumentException(
					output + " is not supported as output");
		}

		XMLSecurityStreamWriter streamWriter =
			new XMLSecurityStreamWriter(outputProcessorChain);
		streamWriter.setSignEntireRequestPart(signEntireRequestPart);
		streamWriter.setEncryptEntireRequestPart(encryptEntireRequestPart);

		return streamWriter;
	}

	static void initializeOutputProcessor(
			OutputProcessorChainImpl outputProcessorChain,
			OutputProcessor outputProcessor, XMLSecurityConstants.Action action,
			XMLSecurityProperties securityProperties)
			throws XMLSecurityException {
		outputProcessor.setXMLSecurityProperties(securityProperties);
		outputProcessor.setAction(action);
		outputProcessor.init(outputProcessorChain);
	}

	static void configureEncryptionKeys(
			final OutboundSecurityContextImpl outboundSecurityContext,
			XMLSecurityProperties securityProperties)
			throws XMLSecurityException {
		// Sort out transport keys / key wrapping keys first.
		Key transportKey = securityProperties.getEncryptionTransportKey();
		X509Certificate transportCert =
			securityProperties.getEncryptionUseThisCertificate();
		X509Certificate[] transportCerts = null;
		if (transportCert != null) {
			transportCerts = new X509Certificate[] {
					transportCert };
		}

		final OutboundSecurityToken transportSecurityToken =
			new GenericOutboundSecurityToken(IDGenerator.generateID(null),
					SecurityTokenConstants.DefaultToken, transportKey,
					transportCerts);

		// Now sort out the session key
		Key key = securityProperties.getEncryptionKey();
		if (key == null) {
			if (transportCert == null && transportKey == null) {
				throw new XMLSecurityException(
						"stax.encryption.encryptionKeyMissing");
			}
			// If none is configured then generate one
			String keyAlgorithm = JCEAlgorithmMapper.getJCEKeyAlgorithmFromURI(
					securityProperties.getEncryptionSymAlgorithm());
			KeyGenerator keyGen;
			try {
				keyGen = KeyGenerator.getInstance(keyAlgorithm);
			} catch (NoSuchAlgorithmException e) {
				throw new XMLSecurityException(e);
			}
			// the sun JCE provider expects the real key size for 3DES (112 or
			// 168 bit)
			// whereas bouncy castle expects the block size of 128 or 192 bits
			if (keyAlgorithm.contains("AES")) {
				int keyLength = JCEAlgorithmMapper.getKeyLengthFromURI(
						securityProperties.getEncryptionSymAlgorithm());
				keyGen.init(keyLength);
			}

			key = keyGen.generateKey();
		}

		final String securityTokenid = IDGenerator.generateID(null);
		final GenericOutboundSecurityToken securityToken =
			new GenericOutboundSecurityToken(securityTokenid,
					SecurityTokenConstants.DefaultToken, key);
		securityToken.setKeyWrappingToken(transportSecurityToken);

		final SecurityTokenProvider<OutboundSecurityToken> securityTokenProvider =
			new SecurityTokenProvider<OutboundSecurityToken>() {

				@Override
				public OutboundSecurityToken getSecurityToken()
						throws XMLSecurityException {
					return securityToken;
				}

				@Override
				public String getId() {
					return securityTokenid;
				}
			};
		outboundSecurityContext.registerSecurityTokenProvider(securityTokenid,
				securityTokenProvider);
		outboundSecurityContext.put(
				XMLSecurityConstants.PROP_USE_THIS_TOKEN_ID_FOR_ENCRYPTION,
				securityTokenid);
	}

	static void configureSignatureKeys(
			final OutboundSecurityContextImpl outboundSecurityContext,
			XMLSecurityProperties securityProperties)
			throws XMLSecurityException {
		Key key = securityProperties.getSignatureKey();
		X509Certificate[] x509Certificates =
			securityProperties.getSignatureCerts();
		if (key instanceof PrivateKey
				&& (x509Certificates == null || x509Certificates.length == 0)
				&& securityProperties.getSignatureVerificationKey() == null) {
			throw new XMLSecurityException(
					"stax.signature.publicKeyOrCertificateMissing");
		}

		final String securityTokenid = IDGenerator.generateID("SIG");
		final OutboundSecurityToken securityToken =
			new GenericOutboundSecurityToken(securityTokenid,
					SecurityTokenConstants.DefaultToken, key, x509Certificates);
		if (securityProperties
				.getSignatureVerificationKey() instanceof PublicKey) {
			((GenericOutboundSecurityToken) securityToken)
					.setPublicKey((PublicKey) securityProperties
							.getSignatureVerificationKey());
		}

		final SecurityTokenProvider<OutboundSecurityToken> securityTokenProvider =
			new SecurityTokenProvider<OutboundSecurityToken>() {

				@Override
				public OutboundSecurityToken getSecurityToken()
						throws XMLSecurityException {
					return securityToken;
				}

				@Override
				public String getId() {
					return securityTokenid;
				}
			};
		outboundSecurityContext.registerSecurityTokenProvider(securityTokenid,
				securityTokenProvider);

		outboundSecurityContext.put(
				XMLSecurityConstants.PROP_USE_THIS_TOKEN_ID_FOR_SIGNATURE,
				securityTokenid);
	}

}
