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

import javax.xml.namespace.QName;

public class TestData {

	public static final String PN_LINE_SEPARATOR = "line.separator";

	public static final String DOC_1 = "plaintext.xml";
	public static final QName DOC_1_ROOT =
		new QName("urn:example:po", "PurchaseOrder");

	public static final String DOC_2 = "plaintext2.xml";
	public static final QName DOC_2_ROOT =
		new QName("urn:example:po", "PurchaseOrders");

	public static final String DOC_3 = "plaintext3.xml";
	public static final QName DOC_3_ROOT =
		new QName("urn:example:po", "PurchaseOrders");

	private static final List<Object[]> PLAINTEXTS = new ArrayList<>();
	static {
		PLAINTEXTS.add(new Object[] {
				DOC_1, DOC_1_ROOT });
		PLAINTEXTS.add(new Object[] {
				DOC_2, DOC_2_ROOT });
		PLAINTEXTS.add(new Object[] {
				DOC_3, DOC_3_ROOT });
	}

	public static List<Object[]> getTestData() {
		List<Object[]> retVal = Collections.unmodifiableList(PLAINTEXTS);
		return retVal;
	}

}
