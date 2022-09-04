package cn.edu.buaa.crypto.encryption.abe.cpabe.waters11.serparams;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.serparams.CPABERW13PublicKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/11/29.
 *
 * Rouselakis-Waters CP-ABE public key parameter.
 */
public class CPABEWATERS11PublicKeySerParameter extends PairingKeySerParameter {
    public transient Element g1;
    private final byte[] byteArrayG1;

    public transient Element g2;
    private final byte[] byteArrayG2;

    private transient Element g1A;
    private final byte[] byteArrayG1A;

    private transient Element g2A;
    private final byte[] byteArrayG2A;

    private transient Element eggAlpha;
    private final byte[] byteArrayEggAlpha;


    //    new CPABEWATERS11PublicKeySerParameter(this.parameters.getPairingParameters(), g1, g2, eggAlpha, g1A, g2A),
//    new CPABEWATERS11MasterSecretKeySerParameter(this.parameters.getPairingParameters(), g1Alpha, g2Alpha));
    public CPABEWATERS11PublicKeySerParameter(
            PairingParameters parameters, Element g1, Element g2, Element eggAlpha, Element g1A, Element g2A) {
        super(false, parameters);

        this.g1 = g1.getImmutable();
        this.byteArrayG1 = this.g1.toBytes();

        this.g2 = g2.getImmutable();
        this.byteArrayG2 = this.g2.toBytes();

        this.g1A = g1A.getImmutable();
        this.byteArrayG1A = this.g1A.toBytes();

        this.g2A = g2A.getImmutable();
        this.byteArrayG2A = this.g2A.toBytes();

        this.eggAlpha = eggAlpha.getImmutable();
        this.byteArrayEggAlpha = this.eggAlpha.toBytes();
    }

    public Element getG1() {
        return g1.duplicate();
    }

    public Element getG2() {
        return g2.duplicate();
    }

    public Element getG1A() {
        return g1A.duplicate();
    }

    public Element getG2A() {
        return g2A.duplicate();
    }

    public Element getEggAlpha() {
        return eggAlpha.duplicate();
    }
    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof CPABEWATERS11PublicKeySerParameter) {
            CPABEWATERS11PublicKeySerParameter that = (CPABEWATERS11PublicKeySerParameter)anObject;
            //Compare g1
            if (!PairingUtils.isEqualElement(this.g1, that.g1)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayG1, that.byteArrayG1)) {
                return false;
            }
            //Compare g2
            if (!PairingUtils.isEqualElement(this.g2, that.g2)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayG2, that.byteArrayG2)) {
                return false;
            }
            //Compare g1a
            if (!PairingUtils.isEqualElement(this.g1A, that.g1A)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayG1A, that.byteArrayG1A)) {
                return false;
            }
            //Compare g2a
            if (!PairingUtils.isEqualElement(this.g2A, that.g2A)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayG2A, that.byteArrayG2A)) {
                return false;
            }
            //Compare eggAlpha
            if (!PairingUtils.isEqualElement(this.eggAlpha, that.eggAlpha)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayEggAlpha, that.byteArrayEggAlpha)) {
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
        this.g1 = pairing.getG1().newElementFromBytes(this.byteArrayG1).getImmutable();
        this.g2 = pairing.getG2().newElementFromBytes(this.byteArrayG2).getImmutable();
        this.g1A = pairing.getG1().newElementFromBytes(this.byteArrayG1A).getImmutable();
        this.g2A = pairing.getG2().newElementFromBytes(this.byteArrayG2A).getImmutable();
        this.eggAlpha = pairing.getGT().newElementFromBytes(this.byteArrayEggAlpha).getImmutable();
    }
}
