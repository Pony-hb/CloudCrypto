package cn.edu.buaa.crypto.encryption.abe.cpabe.waters11.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingKeyParameterGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.genparams.CPABESecretKeyGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.waters11.serparams.CPABEWATERS11MasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.waters11.serparams.CPABEWATERS11PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.waters11.serparams.CPABEWATERS11SecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.waters11.serparams.CPABEWATERS11MasterSecretKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.KeyGenerationParameters;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by Weiran Liu on 2016/11/29.
 *
 * Rouselakia-Waters CP-ABE secret key generator.
 */
public class CPABEWATERS11SecretKeyGenerator implements PairingKeyParameterGenerator {
    protected CPABESecretKeyGenerationParameter parameter;

    public void init(KeyGenerationParameters keyGenerationParameter) {
        this.parameter = (CPABESecretKeyGenerationParameter)keyGenerationParameter;
    }

    public PairingKeySerParameter generateKey() {
        CPABEWATERS11MasterSecretKeySerParameter masterSecretKeyParameter = (CPABEWATERS11MasterSecretKeySerParameter)parameter.getMasterSecretKeyParameter();
        CPABEWATERS11PublicKeySerParameter publicKeyParameter = (CPABEWATERS11PublicKeySerParameter)parameter.getPublicKeyParameter();

        String[] attributes = this.parameter.getAttributes();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        Map<String, Element> Kx = new HashMap<String, Element>();
        Element t = pairing.getZr().newRandomElement().getImmutable();
        Element K = masterSecretKeyParameter.getg2Alpha().mul(publicKeyParameter.getG2A().powZn(t)).getImmutable();
        Element L = publicKeyParameter.getG2().powZn(t).getImmutable();

        for (String attribute : attributes) {
            Element elementAttribute = PairingUtils.MapStringToGroup(pairing, attribute, PairingUtils.PairingGroupType.G1);
            Element Ki = elementAttribute.powZn(t).getImmutable();
            Kx.put(attribute, Ki);
        }
        return new CPABEWATERS11SecretKeySerParameter(publicKeyParameter.getParameters(), K, L, Kx);
    }
}
