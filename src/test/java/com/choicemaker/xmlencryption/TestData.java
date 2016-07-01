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
