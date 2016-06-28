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
package com.choicemaker.utilcopy01;

import java.util.Collections;
import java.util.Map;
import java.util.WeakHashMap;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;

/**
 * Copied from the Apache cxf-core-3.1.6-sources.jar and then pruned to reduce
 * santuario-kms dependencies. This class is originally from the Jakarta Commons
 * Modeler.
 */
public final class DOMUtils {
	private static final Map<ClassLoader, DocumentBuilder> DOCUMENT_BUILDERS = Collections
			.synchronizedMap(new WeakHashMap<ClassLoader, DocumentBuilder>());

	private DOMUtils() {
	}

	private static DocumentBuilder getDocumentBuilder()
			throws ParserConfigurationException {
		ClassLoader loader = Thread.currentThread().getContextClassLoader();
		if (loader == null) {
			loader = DOMUtils.class.getClassLoader();
		}
		if (loader == null) {
			return DocumentBuilderFactory.newInstance().newDocumentBuilder();
		}
		DocumentBuilder factory = DOCUMENT_BUILDERS.get(loader);
		if (factory == null) {
			DocumentBuilderFactory f2 = DocumentBuilderFactory.newInstance();
			f2.setNamespaceAware(true);
			factory = f2.newDocumentBuilder();
			DOCUMENT_BUILDERS.put(loader, factory);
		}
		return factory;
	}

	/**
	 * Creates a new Document object
	 * 
	 * @throws ParserConfigurationException
	 */
	public static Document newDocument() {
		return createDocument();
	}

	public static Document createDocument() {
		try {
			return getDocumentBuilder().newDocument();
		} catch (ParserConfigurationException e) {
			throw new RuntimeException(e);
		}
	}

}
