package cn.edu.buaa.crypto.encryption.abe.cpabe.waters11.generators;

import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.access.UnsatisfiedAccessControlException;
import cn.edu.buaa.crypto.algebra.generators.PairingDecapsulationGenerator;
import cn.edu.buaa.crypto.algebra.generators.PairingDecryptionGenerator;
import cn.edu.buaa.crypto.encryption.abe.cpabe.genparams.CPABEDecryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.waters11.serparams.CPABEWATERS11CiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.waters11.serparams.CPABEWATERS11HeaderSerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.waters11.serparams.CPABEWATERS11PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.waters11.serparams.CPABEWATERS11SecretKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.util.Map;

/**
 * Created by Weiran Liu on 2016/11/29.
 *
 * Rouselakis-Waters CP-ABE decryption generator.
 */
public class CPABEWATERS11DecryptionGenerator implements PairingDecryptionGenerator, PairingDecapsulationGenerator {
    protected CPABEDecryptionGenerationParameter parameter;
    protected Element sessionKey;

    public void init(CipherParameters parameter) {
        this.parameter = (CPABEDecryptionGenerationParameter) parameter;
    }

    protected void computeDecapsulation() throws InvalidCipherTextException {
        CPABEWATERS11PublicKeySerParameter publicKeyParameter = (CPABEWATERS11PublicKeySerParameter) this.parameter.getPublicKeyParameter();
        CPABEWATERS11SecretKeySerParameter secretKeyParameter = (CPABEWATERS11SecretKeySerParameter) this.parameter.getSecretKeyParameter();
        CPABEWATERS11HeaderSerParameter ciphertextParameter = (CPABEWATERS11HeaderSerParameter) this.parameter.getCiphertextParameter();
        AccessControlEngine accessControlEngine = this.parameter.getAccessControlEngine();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        try {
            AccessControlParameter accessControlParameter
                    = accessControlEngine.generateAccessControl(this.parameter.getAccessPolicy(), this.parameter.getRhos());
            Map<String, Element> omegaElementsMap = accessControlEngine.reconstructOmegas(pairing, secretKeyParameter.getAttributes(), accessControlParameter);

            this.sessionKey = pairing.pairing(ciphertextParameter.getC0(), secretKeyParameter.getK());
            Element A = pairing.getGT().newOneElement().getImmutable();
            for (String attribute : omegaElementsMap.keySet()) {
                Element C1 = ciphertextParameter.getC1sAt(attribute);
                Element Kx = secretKeyParameter.getKxsAt(attribute);
                Element C2 = ciphertextParameter.getC2sAt(attribute);
                Element L = secretKeyParameter.getL();

                Element lambda = omegaElementsMap.get(attribute);
                A = A.mul(pairing.pairing(C1, L).mul(pairing.pairing(Kx, C2)).powZn(lambda)).getImmutable();
            }
            sessionKey = sessionKey.div(A).getImmutable();
        } catch (UnsatisfiedAccessControlException e) {
            throw new InvalidCipherTextException("Attributes associated with the ciphertext do not satisfy access policy associated with the secret key.");
        }
    }

    public Element recoverMessage() throws InvalidCipherTextException {
        computeDecapsulation();
        CPABEWATERS11CiphertextSerParameter ciphertextParameter = (CPABEWATERS11CiphertextSerParameter) this.parameter.getCiphertextParameter();
            return ciphertextParameter.getC().div(sessionKey).getImmutable();
    }

    public byte[] recoverKey() throws InvalidCipherTextException {
        computeDecapsulation();
        return this.sessionKey.toBytes();
    }
}
