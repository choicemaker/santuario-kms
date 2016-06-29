package com.choicemaker.xmlencryption;

import java.util.Properties;

import com.choicemaker.utilcopy01.Precondition;

/**
 * An CredentialSet is a named set of properties.
 */
public abstract class CredentialSet {

	private final String name;
	protected final Properties p = new Properties();

	protected CredentialSet(String name) {
		Precondition.assertNonEmptyString("null or blank name", name);
		this.name = name;
	}

	public String getCredentialName() {
		return name;
	}

	public void put(String pname, String pvalue) {
		Precondition.assertNonEmptyString("null or blank name", pname);
		Precondition.assertNonNullArgument("null value", pvalue);
		p.setProperty(pname, pvalue);
	}

	public void putAll(Properties p) {
		Precondition.assertNonNullArgument("null properties", p);
		this.p.clear();
		this.p.putAll(p);
	}

	public String get(String pname) {
		Precondition.assertNonEmptyString("null or blank name", pname);
		String retVal = p.getProperty(pname);
		return retVal;
	}

}
