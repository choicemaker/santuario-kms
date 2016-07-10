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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;

import com.choicemaker.utilcopy01.Precondition;

/**
 * An CredentialSet is a named set of properties.
 */
public class CredentialSet {

	private final String name;
	private final Properties p = new Properties();

	/**
	 * Creates an invalid, empty credential set with the specified name. To
	 * convert this into a set that is valid for some encryption scheme, add the
	 * property values required by the the scheme.
	 * 
	 * @param name
	 *            a non-null, non-blank String
	 */
	public CredentialSet(String name) {
		Precondition.assertNonEmptyString("null or blank name", name);
		this.name = name;
	}

	public String getCredentialName() {
		return name;
	}

	protected Properties getProperties() {
		return p;
	}

	/**
	 * Returns an unmodifiable copy of the properties of this credential set.
	 * 
	 * @return a non-null, unmodifiable Map
	 */
	public Map<String, String> getCredentialPropertiesAsMap() {
		Map<String, String> m = new HashMap<>();
		for (Entry<Object, Object> entry : getProperties().entrySet()) {
			m.put((String) entry.getKey(), (String) entry.getValue());
		}
		return Collections.unmodifiableMap(m);
	}

	public void put(String pname, String pvalue) {
		Precondition.assertNonEmptyString("null or blank name", pname);
		Precondition.assertNonNullArgument("null value", pvalue);
		getProperties().setProperty(pname, pvalue);
	}

	public void putAll(Properties p) {
		Precondition.assertNonNullArgument("null properties", p);
		this.getProperties().clear();
		this.getProperties().putAll(p);
	}

	public String get(String pname) {
		Precondition.assertNonEmptyString("null or blank name", pname);
		String retVal = getProperties().getProperty(pname);
		return retVal;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((name == null) ? 0 : name.hashCode());
		result = prime * result + ((p == null) ? 0 : p.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		CredentialSet other = (CredentialSet) obj;
		if (name == null) {
			if (other.name != null)
				return false;
		} else if (!name.equals(other.name))
			return false;
		if (p == null) {
			if (other.p != null)
				return false;
		} else if (!p.equals(other.p))
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "CredentialSet [name=" + name + "]";
	}

}
