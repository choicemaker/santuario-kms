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

import java.io.StringWriter;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class XMLPrettyPrint {

	public static String print(Element e) {
		final boolean withLineBreaks = true;
		return print(e, withLineBreaks);
	}

	public static String print(final Element e, boolean withLineBreaks) {
		String retVal;
		if (e == null) {
			retVal = null;

		} else {
			try {
				TransformerFactory tf = TransformerFactory.newInstance();
				Transformer transformer = tf.newTransformer();
				transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION,
						"yes");
				transformer.setOutputProperty(OutputKeys.METHOD, "xml");
				final String indentFlag = withLineBreaks ? "yes" : "no";
				transformer.setOutputProperty(OutputKeys.INDENT, indentFlag);
				transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
				transformer.setOutputProperty(
						"{http://xml.apache.org/xslt}indent-amount", "1");
				StringWriter out = new StringWriter();
				transformer.transform(new DOMSource(e), new StreamResult(out));
				retVal = out.toString();
			} catch (TransformerException e1) {
				retVal = e.toString();
			}

		}
		return retVal;
	}

	private XMLPrettyPrint() {
	}

	public static String print(Document d) {
		String retVal;
		if (d == null) {
			retVal = null;

		} else {
			try {
				TransformerFactory tFactory = TransformerFactory.newInstance();
				Transformer transformer = tFactory.newTransformer();
				DOMSource source = new DOMSource(d);
				transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION,
						"no");
				transformer.setOutputProperty(OutputKeys.METHOD, "xml");
				transformer.setOutputProperty(OutputKeys.INDENT, "yes");
				transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
				transformer.setOutputProperty(
						"{http://xml.apache.org/xslt}indent-amount", "1");
				StringWriter out = new StringWriter();
				StreamResult result = new StreamResult(out);
				transformer.transform(source, result);
				retVal = out.toString();
			} catch (TransformerException e1) {
				retVal = e1.toString();
			}

		}
		return retVal;
	}

}
