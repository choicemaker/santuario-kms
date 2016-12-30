package com.choicemaker.xmlencryption;

import java.util.ArrayList;
import java.util.List;

import javax.xml.stream.XMLStreamException;

import org.apache.commons.codec.binary.Base64;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.OutputProcessorChain;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.XMLSecurityUtils;
import org.apache.xml.security.stax.ext.stax.XMLSecAttribute;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;
import org.apache.xml.security.stax.impl.EncryptionPartDef;
import org.apache.xml.security.stax.impl.processor.output.XMLEncryptOutputProcessor;
import org.apache.xml.security.stax.impl.util.IDGenerator;
import org.apache.xml.security.stax.securityToken.OutboundSecurityToken;

public class AwsKmsEncryptOutputProcessor extends XMLEncryptOutputProcessor {
	
//	private final AwsKmsEncryptionScheme es;
//	private final AwsKmsCredentialSet cs;

//	public AwsKmsEncryptOutputProcessor(AwsKmsEncryptionScheme es, AwsKmsCredentialSet cs) throws XMLSecurityException {
//		super();
//		Precondition.assertNonNullArgument("null encryption scheme", es);
//		Precondition.assertNonNullArgument("null credential set", cs);
//		this.es = es;
//		this.cs = cs;
//	}

	public AwsKmsEncryptOutputProcessor() throws XMLSecurityException {
		super();
	}

	@Override
	protected AbstractInternalEncryptionOutputProcessor createInternalEncryptionOutputProcessor(
            EncryptionPartDef encryptionPartDef,
            XMLSecStartElement startElement,
            String encoding,
            final OutboundSecurityToken keyWrappingToken
    ) throws XMLStreamException, XMLSecurityException {

        final AbstractInternalEncryptionOutputProcessor processor =
                new AbstractInternalEncryptionOutputProcessor(encryptionPartDef,
                        startElement,
                        encoding) {

                    @Override
                    protected void createKeyInfoStructure(OutputProcessorChain outputProcessorChain)
                            throws XMLStreamException, XMLSecurityException {
                        if (keyWrappingToken == null) {
                            // Do not write out a KeyInfo element
                            return;
                        }

                        final String encryptionKeyTransportAlgorithm = getSecurityProperties().getEncryptionKeyTransportAlgorithm();

                        createStartElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_dsig_KeyInfo, true, null);

                        List<XMLSecAttribute> attributes = new ArrayList<XMLSecAttribute>(1);
                        String keyId = IDGenerator.generateID("EK");
                        attributes.add(createAttribute(XMLSecurityConstants.ATT_NULL_Id, keyId));
                        createStartElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_xenc_EncryptedKey, true, attributes);

                        attributes = new ArrayList<XMLSecAttribute>(1);
                        attributes.add(createAttribute(XMLSecurityConstants.ATT_NULL_Algorithm, encryptionKeyTransportAlgorithm));
                        createStartElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_xenc_EncryptionMethod, false, attributes);
                        createEndElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_xenc_EncryptionMethod);

                        createStartElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_dsig_KeyInfo, true, null);
                        String keyName = getSecurityProperties().getEncryptionKeyName();
                        XMLSecurityUtils.createKeyNameTokenStructure(this, outputProcessorChain, keyName);
                        createEndElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_dsig_KeyInfo);

                        createStartElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_xenc_CipherData, false, null);
                        createStartElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_xenc_CipherValue, false, null);

                        byte[] encryptedEphemeralKey = keyWrappingToken.getPublicKey().getEncoded();
                        String base64EphemeralKey = new Base64(76, new byte[]{'\n'}).encodeToString(encryptedEphemeralKey);
                        createCharactersAndOutputAsEvent(outputProcessorChain, base64EphemeralKey);

                        createEndElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_xenc_CipherValue);
                        createEndElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_xenc_CipherData);

                        createEndElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_xenc_EncryptedKey);

                        createEndElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_dsig_KeyInfo);
                    }

                };
        processor.getAfterProcessors().add(XMLEncryptOutputProcessor.class.getName());
        return processor;
    }

}
