package com.choicemaker.utilcopy01;

/**
 * Partial copy of the ChoiceMaker-Util SystemPropertyUtils class. For internal
 * use only.
 * 
 * @author rphall
 */
public class SystemPropertyUtils {

	/** Property Name for Line separator ("n" on UNIX) */
	public static final String PN_LINE_SEPARATOR = "line.separator";

	/** Property Value of Line separator ("n" on UNIX) */
	public static final String PV_LINE_SEPARATOR = System
			.getProperty(PN_LINE_SEPARATOR);

}
