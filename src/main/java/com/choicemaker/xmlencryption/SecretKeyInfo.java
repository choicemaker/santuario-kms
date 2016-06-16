package com.choicemaker.xmlencryption;

import java.util.Arrays;

import org.bouncycastle.util.encoders.Base64;
import org.w3c.dom.Element;

public class SecretKeyInfo {

	private final byte[] secret;
	private final byte[] encryptedSecret;
	private final Element keyInfoReference;

	public SecretKeyInfo(byte[] secret, byte[] encryptedSecret,
			Element keyInfo) {
		this.secret = secret;
		this.encryptedSecret = encryptedSecret;
		this.keyInfoReference = keyInfo;
	}

	public byte[] getKey() {
		return this.secret;
	}

	public byte[] getEncryptedSecret() {
		return encryptedSecret;
	}

	public Element getKeyInfoReference() {
		return keyInfoReference;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + Arrays.hashCode(encryptedSecret);
		result = prime
				* result
				+ ((keyInfoReference == null) ? 0 : keyInfoReference
						.hashCode());
		result = prime * result + Arrays.hashCode(secret);
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
		SecretKeyInfo other = (SecretKeyInfo) obj;
		if (!Arrays.equals(encryptedSecret, other.encryptedSecret))
			return false;
		if (keyInfoReference == null) {
			if (other.keyInfoReference != null)
				return false;
		} else if (!keyInfoReference.equals(other.keyInfoReference))
			return false;
		if (!Arrays.equals(secret, other.secret))
			return false;
		return true;
	}

	@Override
	public String toString() {
		byte[] leadingBytes = Arrays.copyOf(encryptedSecret, 3);
		final int from = encryptedSecret.length - 3;
		final int to = encryptedSecret.length;
		byte[] trailingBytes = Arrays
				.copyOfRange(encryptedSecret, from, to);
		String s = Base64.toBase64String(leadingBytes) + "..."
				+ Base64.toBase64String(trailingBytes);
		final boolean withLineBreaks = false;
		String retVal = "SecretKeyInfo [encryptedSecret=" + s
				+ ", keyInfo="
				+ XMLPrettyPrint.print(keyInfoReference, withLineBreaks)
				+ "]";
		return retVal;
	}

}