package com.choicemaker.utilcopy01;

import org.jasypt.encryption.StringEncryptor;
import org.jasypt.encryption.pbe.PBEStringCleanablePasswordEncryptor;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;

/**
 * Partial copy of the ChoiceMaker core ConfigurationUtils class, copied from
 * the com.choicemaker.cm.core project, and then repackaged and pruned, to
 * reduce dependencies of the santuario-kms library. For internal use only.
 */
public class ConfigurationUtils {

	private ConfigurationUtils() {
	}

	// private static final Logger logger = Logger
	// .getLogger(ConfigurationUtils.class.getName());

	public static final String ENC_START = "ENC(";
	protected static final int ENC_START_LEN = ENC_START.length();
	public static final String ENC_END = ")";
	protected static final int ENC_END_LEN = ENC_END.length();

	public static StringEncryptor createTextEncryptor(char[] password) {
		Precondition.assertBoolean("null or empty password", password != null
				&& password.length > 0);
		PBEStringCleanablePasswordEncryptor retVal =
			new StandardPBEStringEncryptor();
		retVal.setPasswordCharArray(password);
		return retVal;
	}

	public static String decryptText(final String s, StringEncryptor encryptor) {
		String retVal = s;
		if (encryptor != null && s != null && s.startsWith(ENC_START)
				&& s.endsWith(ENC_END)) {
			final int stripEnd = s.length() - ENC_END_LEN;
			assert stripEnd >= ENC_START_LEN;
			String s2 = s.substring(ENC_START_LEN, stripEnd);
			retVal = encryptor.decrypt(s2);
		}
		return retVal;
	}

}
