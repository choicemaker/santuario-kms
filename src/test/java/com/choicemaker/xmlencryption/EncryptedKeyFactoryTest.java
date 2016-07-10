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

import static org.junit.Assert.assertTrue;

import java.io.IOException;

import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;

import com.choicemaker.utilcopy01.DOMUtils;

public class EncryptedKeyFactoryTest {

	@Test
	public void testCreateEncryptedKeyElement() throws IOException {
		Document doc = DOMUtils.newDocument();
		SecretKeyInfoFactory skif = new AwsKmsSecretKeyInfoFactory();
		SecretKeyInfo ski = skif.createSessionKey();
		EncryptedKeyFactory ekef = new EncryptedKeyFactory();
		Element e = ekef.createEncryptedKeyElement(doc, ski);
		assertTrue(e != null);
		String tn = e.getTagName();
		assertTrue(tn != null && tn.equals("xenc:EncryptedKey"));
		NodeList nl = e.getChildNodes();
		assertTrue(nl.getLength() == 3);

		// Encryption method
		nl = e.getElementsByTagName("xenc:EncryptionMethod");
		assertTrue(nl.getLength() == 1);
		Element c = (Element) nl.item(0);
		nl = c.getChildNodes();
		assertTrue(nl.getLength() == 0);

		// Key information
		nl = e.getElementsByTagName("ds:KeyInfo");
		assertTrue(nl.getLength() == 1);
		c = (Element) nl.item(0);
		nl = c.getChildNodes();
		assertTrue(nl.getLength() == 1);
		Element g = (Element) nl.item(0);
		tn = g.getTagName();
		assertTrue(tn != null && tn.equals("ds:KeyName"));
		nl = g.getChildNodes();
		assertTrue(nl.getLength() == 1);
		Node n = nl.item(0);
		assertTrue(n instanceof Text);
		Text t = (Text) n;
		assertTrue(t.getTextContent().length() > 0);

		// Cipher data (encrypted secret key expressed in base 64)
		nl = e.getElementsByTagName("xenc:CipherData");
		assertTrue(nl.getLength() == 1);
		c = (Element) nl.item(0);
		nl = c.getChildNodes();
		assertTrue(nl.getLength() == 1);
		g = (Element) nl.item(0);
		tn = g.getTagName();
		assertTrue(tn != null && tn.equals("xenc:CipherValue"));
		nl = g.getChildNodes();
		assertTrue(nl.getLength() == 1);
		n = nl.item(0);
		assertTrue(n instanceof Text);
		t = (Text) n;
		assertTrue(t.getTextContent().length() > 0);
	}

}
