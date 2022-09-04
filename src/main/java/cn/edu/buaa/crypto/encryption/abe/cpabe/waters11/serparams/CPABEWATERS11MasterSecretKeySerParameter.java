package cn.edu.buaa.crypto.encryption.abe.cpabe.waters11.serparams;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/11/29.
 *
 * Rouselakis-Waters CP-ABE master secret key parameter.
 */
public class CPABEWATERS11MasterSecretKeySerParameter extends PairingKeySerParameter {
    private transient Element g1Alpha;
    private final byte[] byteArrayG1Alpha;

    private transient Element g2Alpha;
    private final byte[] byteArrayG2Alpha;
//  new CPABEWATERS11MasterSecretKeySerParameter(this.parameters.getPairingParameters(), g1Alpha, g2Alpha));
    public CPABEWATERS11MasterSecretKeySerParameter(PairingParameters pairingParameters, Element g1Alpha, Element g2Alpha) {
        super(true, pairingParameters);
        this.g1Alpha = g1Alpha.getImmutable();
        this.byteArrayG1Alpha = this.g1Alpha.toBytes();

        this.g2Alpha = g2Alpha.getImmutable();
        this.byteArrayG2Alpha = this.g2Alpha.toBytes();

    }

    public Element getg1Alpha() { return this.g1Alpha.duplicate(); }
    public Element getg2Alpha() { return this.g2Alpha.duplicate(); }
    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof CPABEWATERS11MasterSecretKeySerParameter) {
            CPABEWATERS11MasterSecretKeySerParameter that = (CPABEWATERS11MasterSecretKeySerParameter)anObject;
            //compare alpha
            if (!(PairingUtils.isEqualElement(this.g1Alpha, that.g1Alpha))) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayG1Alpha, that.byteArrayG1Alpha)) {
                return false;
            }

            if (!(PairingUtils.isEqualElement(this.g2Alpha, that.g2Alpha))) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayG2Alpha, that.byteArrayG2Alpha)) {
                return false;
            }
            //Compare Pairing Parameters
            return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }

    private void readObject(java.io.ObjectInputStream objectInputStream)
            throws java.io.IOException, ClassNotFoundException {
        objectInputStream.defaultReadObject();
        Pairing pairing = PairingFactory.getPairing(this.getParameters());
        this.g1Alpha = pairing.getG1().newElementFromBytes(this.byteArrayG1Alpha).getImmutable();
        this.g2Alpha = pairing.getG2().newElementFromBytes(this.byteArrayG2Alpha).getImmutable();
    }
}
