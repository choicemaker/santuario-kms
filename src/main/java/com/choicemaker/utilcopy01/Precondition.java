/*
 * Copyright (c) 2001, 2016 ChoiceMaker LLC and others.
 * All rights reserved. This program and the accompanying materials 
 * are made available under the terms of the Eclipse Public License
 * v1.0 which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 * 
 * Contributors:
 *     ChoiceMaker Technologies, Inc. - initial API and implementation
 *     ChoiceMaker LLC - subsequent revisions and extensions
 */
package com.choicemaker.utilcopy01;

import java.util.logging.Logger;

/**
 * Checks for preconditions to the successful completion of a method. This is a
 * copy of the ChoiceMaker-Util Precondition class, copied from the
 * choicemaker-util project, and then repackaged and pruned, to reduce
 * dependencies of the santuario-kms library. For internal use only.
 * 
 * @author rphall
 */
public class Precondition {

	private static final Logger logger = Logger.getLogger(Precondition.class
			.getName());

	/**
	 * Default message about a false boolean argument. This message should move
	 * to a resource bundle.
	 */
	public static final String MSG_FALSE_BOOLEAN = "precondition violated";

	/**
	 * Default message about a null or blank string. This message should move to
	 * a resource bundle.
	 */
	public static final String MSG_NULL_OR_BLANK_STRING =
		"null or blank String value";

	/**
	 * Default message about invalid null method argument. This message should
	 * move to a resource bundle.
	 */
	public static final String MSG_NULL_OBJECT = "null argument";

	public static void assertBoolean(boolean b) {
		assertBoolean(MSG_FALSE_BOOLEAN, b);
	}

	public static void assertBoolean(String msg, boolean b) {
		if (!b) {
			msg = msg == null ? Precondition.MSG_FALSE_BOOLEAN : msg;
			logger.severe(msg);
			throw new IllegalArgumentException(msg);
		}
	}

	/**
	 * @param sut
	 *            String under test
	 */
	public static void assertNonEmptyString(String sut)
			throws IllegalArgumentException {
		assertNonEmptyString(Precondition.MSG_NULL_OR_BLANK_STRING, sut);
	}

	/**
	 * Confusing signature! Message is first, string under test is second.
	 * 
	 * @param msg
	 *            Message that will be logged if <code>sut<code> is null or
	 * blank
	 * @param sut
	 *            String under test
	 */
	public static void assertNonEmptyString(String msg, String sut)
			throws IllegalArgumentException {
		if (!StringUtils.nonEmptyString(sut)) {
			msg = msg == null ? Precondition.MSG_NULL_OR_BLANK_STRING : msg;
			logger.severe(msg);
			throw new IllegalArgumentException(msg);
		}
	}

	public static void assertNonNullArgument(Object o) {
		assertNonNullArgument(Precondition.MSG_NULL_OBJECT, o);
	}

	public static void assertNonNullArgument(String msg, Object o) {
		if (o == null) {
			msg = msg == null ? Precondition.MSG_NULL_OBJECT : msg;
			logger.severe(msg);
			throw new IllegalArgumentException(msg);
		}
	}

	private Precondition() {
	}

}
