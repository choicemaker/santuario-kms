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

/**
 * Partial copy of the ChoiceMaker-Util StringUtils class, copied from the
 * choicemaker-util project, and then repackaged and pruned, to reduce
 * dependencies of the santuario-kms library. For internal use only.
 */
public class StringUtils {

	/**
	 * Returns <code>true</code> iff <code>s</code> is not null and
	 * <code>s.length() > 0</code> and the string itself is not "NULL".
	 *
	 * @param s
	 *            The string to be tested.
	 * @return whether <code>s</code> is neither <code>null</code> nor
	 *         <code>""</code>.
	 */
	public static boolean nonEmptyString(String s) {
		return s != null && s.trim().length() > 0;
	}

}
