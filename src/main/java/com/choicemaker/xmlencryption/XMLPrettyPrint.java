package com.choicemaker.xmlencryption;

import java.io.StringWriter;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

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
			StringWriter out = new StringWriter();
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

}
