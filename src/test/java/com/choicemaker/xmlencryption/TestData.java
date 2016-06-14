package com.choicemaker.xmlencryption;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class TestData {

	private static final List<String> PLAINTEXTS = new ArrayList<>();
	static {
		PLAINTEXTS.add("plaintext.xml");
		PLAINTEXTS.add("plaintext2.xml");
		PLAINTEXTS.add("plaintext3.xml");
	}

	public static List<String> getTestData() {
		List<String> retVal = Collections.unmodifiableList(PLAINTEXTS);
		return retVal;
	}

}
