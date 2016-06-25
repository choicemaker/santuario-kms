/*******************************************************************************
 * Copyright (c) 2016 ChoiceMaker LLC and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *     ChoiceMaker LLC - initial API and implementation
 *******************************************************************************/
package com.choicemaker.xmlencryption;

import static com.choicemaker.xmlencryption.ErrorCodes.MULTIPLE_ERRORS;
import static com.choicemaker.xmlencryption.ErrorCodes.NO_ERRORS;
import static com.choicemaker.xmlencryption.ErrorCodes.UNKNOWN_ERROR;

import java.io.File;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.logging.Logger;

import com.choicemaker.utilcopy01.StringUtils;

public class EncryptionParameters {

	private static final Logger logger = Logger
			.getLogger(EncryptionParameters.class.getName());

	public static final String PN_ACCESSKEY = "aws.user.accessKey";
	public static final String PN_SECRETKEY = "aws.user.secretKey";
	public static final String PN_MASTERKEY = "aws.kms.masterKey";
	public static final String PN_ENDPOINT = "aws.endpoint";
	public static final String PN_ESCROWKEY = "escrow.rsa.key";

	private final boolean isHelp;
	private final boolean hasAwsParameters;
	private final boolean hasEscrowParameters;
	private final String awsAccessKey;
	private final String awsSecretkey;
	private final String awsMasterKeyId;
	private final String awsEndpoint;
	private final File escrowFile;
	private final File inputFile;

	private final Set<String> errors = new LinkedHashSet<>();
	private final Set<Integer> errorCodes = new LinkedHashSet<>();

	/** Help constructor */
	public EncryptionParameters() {
		this(true, null);
	}

	/** Error constructor */
	public EncryptionParameters(final boolean isHelp, List<String> errors) {
		this.isHelp = isHelp;
		if (errors != null) {
			this.errors.addAll(errors);
		}

		this.awsAccessKey = null;
		this.awsSecretkey = null;
		this.awsMasterKeyId = null;
		this.awsEndpoint = null;
		this.escrowFile = null;
		this.inputFile = null;

		this.hasAwsParameters = false;
		this.hasEscrowParameters = false;

		logger.fine(this.toString());
	}

	/** Properties constructor */
	public EncryptionParameters(final boolean isHelp, List<String> errors,
			Properties p, File inputFile) {

		this.isHelp = isHelp;
		if (errors != null) {
			this.errors.addAll(errors);
		}

		if (p != null) {
			this.awsAccessKey = p.getProperty(PN_ACCESSKEY);
			this.awsSecretkey = p.getProperty(PN_SECRETKEY);
			this.awsMasterKeyId = p.getProperty(PN_MASTERKEY);
			this.awsEndpoint = p.getProperty(PN_ENDPOINT);
			String escrowFileName = p.getProperty(PN_ESCROWKEY);
			if (escrowFileName != null) {
				File f = new File(escrowFileName);
				if (f.exists()) {
					this.escrowFile = f;
				} else {
					this.escrowFile = null;
				}
			} else {
				this.escrowFile = null;
			}
			this.inputFile = inputFile;

		} else {
			this.awsAccessKey = null;
			this.awsSecretkey = null;
			this.awsMasterKeyId = null;
			this.awsEndpoint = null;
			this.escrowFile = null;
			this.inputFile = inputFile;
		}

		this.hasAwsParameters = StringUtils.nonEmptyString(awsAccessKey)
				&& StringUtils.nonEmptyString(awsSecretkey)
				&& StringUtils.nonEmptyString(awsMasterKeyId);
		this.hasEscrowParameters = escrowFile != null && escrowFile.exists();
	}

	public boolean isHelp() {
		return isHelp;
	}

	public boolean hasAwsParameters() {
		return hasAwsParameters;
	}

	public boolean hasEscrowParameters() {
		return hasEscrowParameters;
	}

	public boolean hasErrors() {
		assert errors != null;
		return errors.size() > 0;
	}

	public String getAwsAccessKey() {
		return awsAccessKey;
	}

	public String getAwsSecretkey() {
		return awsSecretkey;
	}

	public String getAwsMasterKeyId() {
		return awsMasterKeyId;
	}

	public String getAwsEndpoint() {
		return awsEndpoint;
	}

	public File getEscrowFile() {
		return escrowFile;
	}

	public File getInputFile() {
		return inputFile;
	}

	public Set<String> getErrors() {
		return Collections.unmodifiableSet(errors);
	}

	public Set<Integer> getErrorCodes() {
		return Collections.unmodifiableSet(errorCodes);
	}

	public int computeSummaryCode() {
		int retVal = NO_ERRORS;

		// Collect the meaningful error codes (exclude NO_ERRORS)
		if (this.errorCodes.remove(NO_ERRORS)) {
			logger.warning("removed NO_ERRORS from error codes");
		}

		if (this.errors.size() == 0 && this.errorCodes.size() == 0) {
			assert retVal == NO_ERRORS;

		} else if (this.errors.size() > 0 && this.errorCodes.size() == 0) {
			retVal = UNKNOWN_ERROR;

		} else if (this.errors.size() <= 1 && this.errorCodes.size() == 1) {
			retVal = this.errorCodes.iterator().next();

		} else {
			assert this.errors.size() > 1 || this.errorCodes.size() > 1;
			retVal = MULTIPLE_ERRORS;

		}

		// Log when the API isn't used correctly
		if (retVal != NO_ERRORS && this.errors.size() == 0) {
			logger.warning("No error details for error code: " + retVal);
		}

		return retVal;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result
				+ ((awsAccessKey == null) ? 0 : awsAccessKey.hashCode());
		result = prime * result
				+ ((awsMasterKeyId == null) ? 0 : awsMasterKeyId.hashCode());
		result = prime * result
				+ ((awsSecretkey == null) ? 0 : awsSecretkey.hashCode());
		result = prime * result + ((errors == null) ? 0 : errors.hashCode());
		result = prime * result
				+ ((escrowFile == null) ? 0 : escrowFile.hashCode());
		result = prime * result + (hasErrors() ? 1231 : 1237);
		result = prime * result
				+ ((inputFile == null) ? 0 : inputFile.hashCode());
		result = prime * result + (isHelp ? 1231 : 1237);
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		EncryptionParameters other = (EncryptionParameters) obj;
		if (awsAccessKey == null) {
			if (other.awsAccessKey != null)
				return false;
		} else if (!awsAccessKey.equals(other.awsAccessKey))
			return false;
		if (awsMasterKeyId == null) {
			if (other.awsMasterKeyId != null)
				return false;
		} else if (!awsMasterKeyId.equals(other.awsMasterKeyId))
			return false;
		if (awsSecretkey == null) {
			if (other.awsSecretkey != null)
				return false;
		} else if (!awsSecretkey.equals(other.awsSecretkey))
			return false;
		if (errors == null) {
			if (other.errors != null)
				return false;
		} else if (!errors.equals(other.errors))
			return false;
		if (escrowFile == null) {
			if (other.escrowFile != null)
				return false;
		} else if (!escrowFile.equals(other.escrowFile))
			return false;
		if (inputFile == null) {
			if (other.inputFile != null)
				return false;
		} else if (!inputFile.equals(other.inputFile))
			return false;
		if (isHelp != other.isHelp)
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "EncryptionParameters [isHelp=" + isHelp + ", hasAwsParameters="
				+ hasAwsParameters + ", hasEscrowParameters="
				+ hasEscrowParameters + ", hasErrors=" + hasErrors()
				+ ", inputFile=" + inputFile + "]";
	}

}
