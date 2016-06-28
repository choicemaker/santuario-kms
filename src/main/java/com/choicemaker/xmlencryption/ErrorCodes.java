package com.choicemaker.xmlencryption;

/**
 * Defines error for various problems. These error codes are reused as exit
 * codes for command line applications, so for consistency with reserved Bash
 * exit codes, application-specific error codes are defined in the range 64 to
 * 113, inclusive.
 * 
 * @author rphall
 */
public interface ErrorCodes {

	int NO_ERRORS = 0;
	int ERROR_VERB_ERROR = 64;
	int ERROR_EXTRA_ARGS = 65;

	int MULTIPLE_ERRORS = 111;
	int ERROR_NOT_YET_IMPLEMENTED = 112;
	int UNKNOWN_ERROR = 113;

}
