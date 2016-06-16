package com.choicemaker.xmlencryption;

import java.nio.ByteBuffer;
import java.util.logging.Logger;

import org.apache.cxf.helpers.DOMUtils;
import org.apache.wss4j.dom.WSConstants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.services.kms.model.GenerateDataKeyResult;
import com.choicemaker.util.Precondition;

public class SecretKeyInfoFactory {

	private static final Logger logger = Logger
			.getLogger(SecretKeyInfoFactory.class.getName());

	public static final String endpointFromARN(String arn) {
		String region = parseRegionfromKeyArn(arn);
		if (region == null) {
			throw new IllegalArgumentException("Not an ARN: '" + arn + "'");
		}
		String retVal = "https://kms." + region + ".amazonaws.com";
		return retVal;
	}

	/**
	 * From {@link KmsMasterKeyProvider.parseRegionfromKeyArn(String)}
	 * 
	 * @param keyArn
	 * @return
	 */
	private static String parseRegionfromKeyArn(final String keyArn) {
		final String[] parts = keyArn.split(":", 5);

		if (!parts[0].equals("arn")) {
			// Not an arn
			return null;
		}
		// parts[1].equals("aws"); // This can vary
		if (!parts[2].equals("kms")) {
			// Not a kms arn
			return null;
		}
		return parts[3]; // return region
	}

	private final String endpoint;
	private final String masterKeyId;
	private final String algorithm;
	private final AWSCredentials creds;

	public SecretKeyInfoFactory(String masterKeyARN) {
		this(masterKeyARN, AwsKmsUtils.DEFAULT_AWS_KEY_ENCRYPTION_ALGORITHM, null,
				AwsKmsUtils.getDefaultAWSCredentials());
	}

	public SecretKeyInfoFactory(String masterKeyARN, String algorithm) {
		this(masterKeyARN, algorithm, null, AwsKmsUtils.getDefaultAWSCredentials());
	}

	public SecretKeyInfoFactory(String masterKeyId, String algorithm,
			String endPoint) {
		this(masterKeyId, algorithm, endPoint, AwsKmsUtils.getDefaultAWSCredentials());
	}

	public SecretKeyInfoFactory(String masterKeyId, String algorithm,
			String endPoint, AWSCredentials creds) {

		Precondition.assertNonEmptyString("null or blank master key id",
				masterKeyId);
		Precondition.assertNonEmptyString("null or blank algorithm", algorithm);
		Precondition.assertNonNullArgument("null credentials", creds);
		// endPoint may be null or blank

		this.masterKeyId = masterKeyId;
		this.algorithm = algorithm;
		this.endpoint = endPoint;
		this.creds = creds;
	}

	public SecretKeyInfo createSessionKey() {

		GenerateDataKeyResult dataKeyResult = AwsKmsUtils.generateDataKey(creds,
				masterKeyId, algorithm, endpoint);

		ByteBuffer plaintextKey = dataKeyResult.getPlaintext();
		final byte[] key = new byte[plaintextKey.remaining()];
		plaintextKey.get(key);

		ByteBuffer encryptedKey = dataKeyResult.getCiphertextBlob();
		final byte[] encKey = new byte[encryptedKey.remaining()];
		encryptedKey.get(encKey);

		// Create a KeyName pointing to the encryption key
		Document doc = DOMUtils.newDocument();
		final Element keyInfoElement = doc.createElementNS(WSConstants.SIG_NS,
				WSConstants.SIG_PREFIX + ":" + WSConstants.KEYINFO_LN);
		keyInfoElement.setAttributeNS(WSConstants.XMLNS_NS, "xmlns:"
				+ WSConstants.SIG_PREFIX, WSConstants.SIG_NS);
		Element keyNameElement = doc.createElementNS(WSConstants.SIG_NS,
				WSConstants.SIG_PREFIX + ":KeyName");
		keyNameElement.setTextContent(masterKeyId);
		keyInfoElement.appendChild(keyNameElement);

		SecretKeyInfo retVal = new SecretKeyInfo(key, encKey, /* getAlgorithm(), */
		keyInfoElement);
		logger.fine(retVal.toString());

		return retVal;
	}

	public String getEndpoint() {
		return endpoint;
	}

	public String getMasterKeyId() {
		return masterKeyId;
	}

	public String getAlgorithm() {
		return algorithm;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result
				+ ((algorithm == null) ? 0 : algorithm.hashCode());
		result = prime * result
				+ ((endpoint == null) ? 0 : endpoint.hashCode());
		result = prime * result
				+ ((masterKeyId == null) ? 0 : masterKeyId.hashCode());
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
		SecretKeyInfoFactory other = (SecretKeyInfoFactory) obj;
		if (algorithm == null) {
			if (other.algorithm != null)
				return false;
		} else if (!algorithm.equals(other.algorithm))
			return false;
		if (endpoint == null) {
			if (other.endpoint != null)
				return false;
		} else if (!endpoint.equals(other.endpoint))
			return false;
		if (masterKeyId == null) {
			if (other.masterKeyId != null)
				return false;
		} else if (!masterKeyId.equals(other.masterKeyId))
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "SecretKeyInfoFactory [masterKeyId=" + masterKeyId
				+ ", algorithm=" + algorithm + "]";
	}

}
