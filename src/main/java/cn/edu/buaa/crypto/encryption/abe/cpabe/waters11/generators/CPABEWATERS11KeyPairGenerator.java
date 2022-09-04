package cn.edu.buaa.crypto.encryption.abe.cpabe.waters11.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingKeyPairGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.encryption.abe.cpabe.genparams.CPABEKeyPairGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.waters11.serparams.CPABEWATERS11MasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.waters11.serparams.CPABEWATERS11PublicKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/11/29.
 *
 * Rouselakis-Waters CP-ABE public key / master secret key generator.
 */
public class CPABEWATERS11KeyPairGenerator implements PairingKeyPairGenerator {
    protected CPABEKeyPairGenerationParameter parameters;

    public void init(KeyGenerationParameters keyGenerationParameter) {
        this.parameters = (CPABEKeyPairGenerationParameter) keyGenerationParameter;
    }

    public PairingKeySerPair generateKeyPair() {
        Pairing pairing = PairingFactory.getPairing(this.parameters.getPairingParameters());

        Element g1 = pairing.getG1().newRandomElement().getImmutable();
        Element g2 = pairing.getG2().newRandomElement().getImmutable();

        Element alpha = pairing.getZr().newRandomElement().getImmutable();
        Element a = pairing.getZr().newRandomElement().getImmutable();


        Element g1Alpha = g1.powZn(alpha).getImmutable();
        Element g2Alpha = g2.powZn(alpha).getImmutable();
        Element eggAlpha = pairing.pairing(g1, g2).powZn(alpha).getImmutable();

        Element g1A = g1.powZn(a).getImmutable();
        Element g2A = g2.powZn(a).getImmutable();

        return new PairingKeySerPair(
                new CPABEWATERS11PublicKeySerParameter(this.parameters.getPairingParameters(), g1, g2, eggAlpha, g1A, g2A),
                new CPABEWATERS11MasterSecretKeySerParameter(this.parameters.getPairingParameters(), g1Alpha, g2Alpha));
    }
}