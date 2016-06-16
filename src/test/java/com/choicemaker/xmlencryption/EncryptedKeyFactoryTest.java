package com.choicemaker.xmlencryption;

import static org.junit.Assert.assertTrue;

import org.apache.cxf.helpers.DOMUtils;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;

public class EncryptedKeyFactoryTest {

	public static final String MASTER_KEY_ARN = "arn:aws:kms:us-east-1:073204089135:key/b4985799-964b-4383-8b91-9d82d866858d";

	@Test
	public void testCreateEncryptedKeyElement() {
		Document doc = DOMUtils.newDocument();
		SecretKeyInfoFactory skif = new SecretKeyInfoFactory(MASTER_KEY_ARN);
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
