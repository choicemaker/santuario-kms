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
 * Partial copy of the ChoiceMaker-Util SystemPropertyUtils class, copied from
 * the choicemaker-util project, and then repackaged and pruned, to reduce
 * dependencies of the santuario-kms library. For internal use only.
 * 
 * @author rphall
 */
public class SystemPropertyUtils {

	/** Property Name for File separator ("/" on UNIX) */
	public static final String PN_FILE_SEPARATOR = "file.separator";

	/** Property Value of File separator ("/" on UNIX) */
	public static final String PV_FILE_SEPARATOR = System
			.getProperty(PN_FILE_SEPARATOR);

	/** Property Name for Line separator ("n" on UNIX) */
	public static final String PN_LINE_SEPARATOR = "line.separator";

	/** Property Value of Line separator ("n" on UNIX) */
	public static final String PV_LINE_SEPARATOR = System
			.getProperty(PN_LINE_SEPARATOR);

	/** Property Name for User's home directory */
	public static final String PN_USER_HOME = "user.home";

	/** Property Value of User's home directory */
	public static final String PV_USER_HOME = System.getProperty(PN_USER_HOME);

}
