package com.choicemaker.xmlencryption;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.w3c.dom.Element;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.choicemaker.utilcopy01.Precondition;
import com.choicemaker.utilcopy01.StringUtils;

public class AwsKmsEncryptionScheme implements EncryptionScheme {

	// private static final Logger logger = Logger
	// .getLogger(AwsKmsEncryptionScheme.class.getName());

	public static final CryptoAlgorithm DEFAULT_ALGORITHM = CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256;

	public static final String PN_ACCESSKEY = EncryptionParameters.PN_ACCESSKEY;
	public static final String PN_SECRETKEY = EncryptionParameters.PN_SECRETKEY;
	public static final String PN_MASTERKEY = EncryptionParameters.PN_MASTERKEY;
	public static final String PN_ENDPOINT = EncryptionParameters.PN_ENDPOINT;

	private static final String[] REQUIRED_PROPERTY_NAMES = new String[] {
			PN_ACCESSKEY, PN_SECRETKEY, PN_MASTERKEY };

	public static SecretKeyInfo createSessionKey(AWSCredentials creds,
			String masterKeyId, String algorithm, String endpoint) {
		return AwsKmsSecretKeyInfoFactory.createSessionKey(creds, masterKeyId,
				algorithm, endpoint);
	}

	public Set<String> getRequiredPropertyNames() {
		Set<String> retVal = new HashSet<>();
		retVal.addAll(Arrays.asList(REQUIRED_PROPERTY_NAMES));
		return Collections.unmodifiableSet(retVal);
	}

	@Override
	public boolean isConsistentWithEncryption(CredentialSet ec) {
		boolean retVal = ec != null;
		if (retVal) {
			for (String pn : getRequiredPropertyNames()) {
				String value = ec.get(pn);
				if (!StringUtils.nonEmptyString(value)) {
					retVal = false;
				}
			}
		}
		return retVal;
	}

	@Override
	public boolean isConsistentWithDecryption(CredentialSet ec) {
		return isConsistentWithEncryption(ec);
	}

	public CryptoAlgorithm getDefaultAlgorithm() {
		return DEFAULT_ALGORITHM;
	}

	@Override
	public String getSchemeId() {
		return AwsKmsEncryptionScheme.class.getName();
	}

	@Override
	public SecretKeyInfoFactory getSecretKeyInfoFactory(
			CredentialSet ec, String algorithmName,
			Map<String, String> unused) {
		Precondition.assertNonNullArgument("null credential", ec);
		Precondition.assertBoolean(isConsistentWithEncryption(ec));
		Precondition.assertNonEmptyString("null or blank algorithm name",
				algorithmName);

		final String masterKeyId = getMasterKeyId(ec);
		final String endpoint = getEndpoint(ec);
		final AWSCredentials creds = getAwsKmsCredentials(ec);

		SecretKeyInfoFactory retVal = new AwsKmsSecretKeyInfoFactory(
				masterKeyId, algorithmName, endpoint, creds);
		return retVal;
	}

	@Override
	public SecretKeyInfo recoverSecretKeyInfo(Element encryptedKeyElement) {
		// TODO Auto-generated method stub
		throw new Error("not yet implemented");
	}

	@Override
	public String getDefaultAlgorithmName() {
		return getDefaultAlgorithm().name();
	}

	public String getEndpoint(CredentialSet ec) {
		String retVal = ec.get(PN_ENDPOINT);
		return retVal;
	}

	public AWSCredentials getAwsKmsCredentials(CredentialSet ec) {
		String accessKey = ec.get(PN_ACCESSKEY);
		String secretKey = ec.get(PN_SECRETKEY);
		AWSCredentials retVal = new BasicAWSCredentials(accessKey, secretKey);
		return retVal;
	}

	public String getMasterKeyId(CredentialSet ec) {
		String retVal = ec.get(PN_MASTERKEY);
		return retVal;
	}

}
