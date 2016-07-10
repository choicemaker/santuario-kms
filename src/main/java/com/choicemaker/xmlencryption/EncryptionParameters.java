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

public class EncryptionParameters {

	private static final Logger logger = Logger
			.getLogger(EncryptionParameters.class.getName());

	public static final String PN_ESCROWKEY = "escrow.rsa.key";

	private final boolean isHelp;
	private final boolean hasAwsParameters;
	private final boolean hasEscrowParameters;
	private final EncryptionScheme es;
	private final CredentialSet cs;
	private final File escrowFile;
	private final File inputFile;

	/** Cached copy of CredentialSet properties */
	private final Properties p;

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

		this.es = null;
		this.cs = null;
		this.p = null;
		this.escrowFile = null;
		this.inputFile = null;

		this.hasAwsParameters = false;
		this.hasEscrowParameters = false;

		logger.fine(this.toString());
	}

	/** Properties constructor */
	public EncryptionParameters(final boolean isHelp, List<String> errors,
			EncryptionScheme es, CredentialSet cs, File inputFile) {

		this.isHelp = isHelp;
		if (errors != null) {
			this.errors.addAll(errors);
		}

		this.es = es;
		this.cs = cs;
		this.inputFile = inputFile;
		this.p = cs == null ? null : cs.getProperties();
		if (p != null) {
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

		} else {
			this.escrowFile = null;
		}

		this.hasAwsParameters = AwsKmsProperties.hasAwsParameters(p);
		this.hasEscrowParameters = escrowFile != null && escrowFile.exists();
	}

	public EncryptionScheme getEncryptionScheme() {
		return es;
	}

	public CredentialSet getCredentialSet() {
		return cs;
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
		return p == null ? null : AwsKmsProperties.getAccessKey(p);
	}

	public String getAwsSecretkey() {
		return p == null ? null : AwsKmsProperties.getSecretKey(p);
	}

	public String getAwsMasterKeyId() {
		return p == null ? null : AwsKmsProperties.getMasterKeyId(p);
	}

	public String getAwsEndpoint() {
		return p == null ? null : AwsKmsProperties.getEndpoint(p);
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
		result = prime * result + ((cs == null) ? 0 : cs.hashCode());
		result =
			prime * result + ((errorCodes == null) ? 0 : errorCodes.hashCode());
		result = prime * result + ((errors == null) ? 0 : errors.hashCode());
		result = prime * result + ((es == null) ? 0 : es.hashCode());
		result =
			prime * result + ((inputFile == null) ? 0 : inputFile.hashCode());
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
		if (cs == null) {
			if (other.cs != null)
				return false;
		} else if (!cs.equals(other.cs))
			return false;
		if (errorCodes == null) {
			if (other.errorCodes != null)
				return false;
		} else if (!errorCodes.equals(other.errorCodes))
			return false;
		if (errors == null) {
			if (other.errors != null)
				return false;
		} else if (!errors.equals(other.errors))
			return false;
		if (es == null) {
			if (other.es != null)
				return false;
		} else if (!es.equals(other.es))
			return false;
		if (inputFile == null) {
			if (other.inputFile != null)
				return false;
		} else if (!inputFile.equals(other.inputFile))
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
