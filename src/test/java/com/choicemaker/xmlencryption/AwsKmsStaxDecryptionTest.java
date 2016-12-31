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

import static com.choicemaker.xmlencryption.AwsKmsStaxEncryptionTest.encryptEntireDocUsingStAX;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;

import org.apache.xml.security.stax.impl.processor.output.XMLEncryptOutputProcessor;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.Assert;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/**
 * Encrypts an entire document via StAX, but encryption fails for some documents
 * because the document root is left as plain text
 */
public class AwsKmsStaxDecryptionTest extends org.junit.Assert {

	static {
		org.apache.xml.security.Init.init();
	}

	// Encrypt using StAX, then decrypt using StAX
	public void testStAXDecryption(String docName, QName root)
			throws Exception {

		// Read in cleartext document
		InputStream clearSource =
			this.getClass().getClassLoader().getResourceAsStream(docName);
		final DocumentBuilder documentBuilder =
			XMLUtils.createDocumentBuilder(false);
		final Document clearDoc = documentBuilder.parse(clearSource);
		XMLUtils.outputDOM(clearDoc, System.out);
		final Element clearRoot = clearDoc.getDocumentElement();
		final String clearRootNS = clearRoot.getNamespaceURI();
		final String clearRootLN = clearRoot.getLocalName();

		// Encrypt entire document using StAX
		clearSource.close();
		clearSource =
			this.getClass().getClassLoader().getResourceAsStream(docName);
//		XMLEncryptOutputProcessor encryptOutputProcessor =
//				new AwsKmsEncryptOutputProcessor();
		XMLEncryptOutputProcessor encryptOutputProcessor =
				new XMLEncryptOutputProcessor();
		final ByteArrayOutputStream baosEncrypted =
			encryptEntireDocUsingStAX(clearSource, encryptOutputProcessor);

		// Decrypt the encrypted document
		InputStream encryptedSource =
			new ByteArrayInputStream(baosEncrypted.toByteArray());
		final ByteArrayOutputStream baosDecrypted =
				decryptEntireDocUsingStAX(encryptedSource);
		
		clearSource = new ByteArrayInputStream(baosDecrypted.toByteArray());
		Document decryptedDoc = documentBuilder.parse(clearSource);
		XMLUtils.outputDOM(decryptedDoc, System.out);

		// Check that the root is not encrypted
		NodeList encryptedNodes =
				decryptedDoc.getElementsByTagNameNS(clearRootNS, clearRootLN);
		Assert.assertEquals("unencrypted root", encryptedNodes.getLength(), 1);

		// Check that the root has at least one child and that no child is
		// encrypted
		Element r = (Element) encryptedNodes.item(0);
		NodeList clist = r.getChildNodes();
		Assert.assertTrue("zero nodes", clist.getLength() > 0);
		for (int i = 0; i < clist.getLength(); i++) {
			Element c = (Element) clist.item(i);
			String cln = c.getLocalName();
			Assert.assertNotEquals("content encrypted", cln, "EncryptedData");
		}
	}

	private ByteArrayOutputStream decryptEntireDocUsingStAX(
			InputStream clearSource) {
		// TODO Auto-generated method stub
		return null;
	}

}
