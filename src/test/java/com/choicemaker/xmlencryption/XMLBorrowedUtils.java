package com.choicemaker.xmlencryption;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.stream.events.XMLEvent;

class XMLBorrowedUtils {

	private XMLBorrowedUtils() {}

	/**
	 * Borrowed from org.apache.xml.security.test.stax.utils.XmlReaderToWriter
	 */
	public static void writeAll(XMLStreamReader xmlr, XMLStreamWriter writer)
			throws XMLStreamException {
		while (xmlr.hasNext()) {
			xmlr.next();
			write(xmlr, writer);
		}
		writer.flush();
	}

	/**
	 * Borrowed from org.apache.xml.security.test.stax.utils.XmlReaderToWriter
	 */
	public static void write(XMLStreamReader xmlr, XMLStreamWriter writer)
			throws XMLStreamException {
		switch (xmlr.getEventType()) {
		case XMLEvent.START_ELEMENT:
			final String localName = xmlr.getLocalName();
			final String namespaceURI = xmlr.getNamespaceURI();
			if (namespaceURI != null && namespaceURI.length() > 0) {
				final String prefix = xmlr.getPrefix();
				if (prefix != null) {
					writer.writeStartElement(prefix, localName, namespaceURI);
				} else {
					writer.writeStartElement(namespaceURI, localName);
				}
			} else {
				writer.writeStartElement(localName);
			}
	
			for (int i = 0, len = xmlr.getNamespaceCount(); i < len; i++) {
				String prefix = xmlr.getNamespacePrefix(i);
				if (prefix == null) {
					writer.writeDefaultNamespace(xmlr.getNamespaceURI(i));
				} else {
					writer.writeNamespace(prefix, xmlr.getNamespaceURI(i));
				}
			}
	
			for (int i = 0, len = xmlr.getAttributeCount(); i < len; i++) {
				final String attUri = xmlr.getAttributeNamespace(i);
	
				if (attUri != null && attUri.length() > 0) {
					final String prefix = xmlr.getAttributePrefix(i);
					if (prefix != null) {
						writer.writeAttribute(prefix, attUri, xmlr.getAttributeLocalName(i), xmlr.getAttributeValue(i));
					} else {
						writer.writeAttribute(attUri, xmlr.getAttributeLocalName(i), xmlr.getAttributeValue(i));
					}
				} else {
					writer.writeAttribute(xmlr.getAttributeLocalName(i), xmlr.getAttributeValue(i));
				}
	
			}
			break;
		case XMLEvent.END_ELEMENT:
			writer.writeEndElement();
			break;
		case XMLEvent.SPACE:
		case XMLEvent.CHARACTERS:
			char[] text = new char[xmlr.getTextLength()];
			xmlr.getTextCharacters(0, text, 0, xmlr.getTextLength());
			writer.writeCharacters(text, 0, text.length);
			break;
		case XMLEvent.PROCESSING_INSTRUCTION:
			writer.writeProcessingInstruction(xmlr.getPITarget(),
					xmlr.getPIData());
			break;
		case XMLEvent.CDATA:
			writer.writeCData(xmlr.getText());
			break;
		case XMLEvent.COMMENT:
			writer.writeComment(xmlr.getText());
			break;
		case XMLEvent.ENTITY_REFERENCE:
			writer.writeEntityRef(xmlr.getLocalName());
			break;
		case XMLEvent.START_DOCUMENT:
			String encoding = xmlr.getCharacterEncodingScheme();
			String version = xmlr.getVersion();
	
			if (encoding != null && version != null) {
				writer.writeStartDocument(encoding, version);
			} else if (version != null) {
				writer.writeStartDocument(xmlr.getVersion());
			}
			break;
		case XMLEvent.END_DOCUMENT:
			writer.writeEndDocument();
			break;
		case XMLEvent.DTD:
			writer.writeDTD(xmlr.getText());
			break;
		}
	}
	
}
