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

import org.w3c.dom.Attr;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;

/**
 * Copied from wss4j-ws-security-common-2.1.5-sources.jar, and then pruned, to
 * reduce dependencies of the santuario-kms library.
 */
public final class XMLUtils {

	public static final String XMLNS_NS = "http://www.w3.org/2000/xmlns/";

	private XMLUtils() {
		// complete
	}

	/**
	 * Set a namespace/prefix on an element if it is not set already. First off,
	 * it searches for the element for the prefix associated with the specified
	 * namespace. If the prefix isn't null, then this is returned. Otherwise, it
	 * creates a new attribute using the namespace/prefix passed as parameters.
	 *
	 * @param element
	 * @param namespace
	 * @param prefix
	 * @return the prefix associated with the set namespace
	 */
	public static String setNamespace(Element element, String namespace,
			String prefix) {
		String pre = getPrefixNS(namespace, element);
		if (pre != null) {
			return pre;
		}
		element.setAttributeNS(XMLNS_NS, "xmlns:" + prefix, namespace);
		return prefix;
	}

	public static String getPrefixNS(String uri, Node e) {
		while (e != null && e.getNodeType() == Node.ELEMENT_NODE) {
			NamedNodeMap attrs = e.getAttributes();
			for (int n = 0; n < attrs.getLength(); n++) {
				Attr a = (Attr) attrs.item(n);
				String name = a.getName();
				if (name.startsWith("xmlns:") && a.getNodeValue().equals(uri)) {
					return name.substring("xmlns:".length());
				}
			}
			e = e.getParentNode();
		}
		return null;
	}

}
