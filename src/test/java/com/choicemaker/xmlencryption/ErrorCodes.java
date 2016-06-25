package com.choicemaker.xmlencryption;

/**
 * Defines error and exit codes for the various contexts, including command line
 * applications. For consistency with reserved Bash exit codes,
 * application-specific exit codes are defined in the range 64 to 113,
 * inclusive.
 * 
 * @author rphall
 */
public interface ErrorCodes {

	int EXIT_SUCCESS = 0;
	int EXIT_VERB_ERROR = 64;
	int EXIT_EXTRA_ARGS = 65;

	int EXIT_MULTIPLE_ERRORS = 111;
	int EXIT_NOT_YET_IMPLEMENTED = 112;
	int EXIT_UNKNOWN_ERROR = 113;

	int NO_ERRORS = EXIT_SUCCESS;
	int ERROR_VERB_ERROR = EXIT_VERB_ERROR;
	int ERROR_EXTRA_ARGS = EXIT_EXTRA_ARGS;

	int MULTIPLE_ERRORS = EXIT_MULTIPLE_ERRORS;
	int ERROR_NOT_YET_IMPLEMENTED = EXIT_NOT_YET_IMPLEMENTED;
	int UNKNOWN_ERROR = EXIT_UNKNOWN_ERROR;

}
