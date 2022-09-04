package cn.edu.buaa.crypto.encryption.abe.cpabe.waters11.serparams;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by Weiran Liu on 2016/11/29.
 *
 * Rouselakis-Waters CP-ABE secret key parameter.
 */
public class CPABEWATERS11SecretKeySerParameter extends PairingKeySerParameter {
    private transient Element K;
    private final byte[] byteArrayK;

    private transient Element L;
    private final byte[] byteArrayL;

    private transient Map<String, Element> Kx;
    private final Map<String, byte[]> byteArraysKx;



    public CPABEWATERS11SecretKeySerParameter(PairingParameters pairingParameters, Element K, Element L,
                                              Map<String, Element> Kx) {
        super(true, pairingParameters);

        this.K = K.getImmutable();
        this.byteArrayK = this.K.toBytes();

        this.L = L.getImmutable();
        this.byteArrayL = this.L.toBytes();

        this.Kx = new HashMap<String, Element>();
        this.byteArraysKx = new HashMap<String, byte[]>();

        for (String attribute : Kx.keySet()) {
            this.Kx.put(attribute, Kx.get(attribute).duplicate().getImmutable());
            this.byteArraysKx.put(attribute, Kx.get(attribute).duplicate().getImmutable().toBytes());
        }
    }

    public String[] getAttributes() { return this.Kx.keySet().toArray(new String[1]); }

    public Element getK() { return this.K.duplicate(); }

    public Element getL() { return this.L.duplicate(); }

    public Map<String, Element> getKx() { return this.Kx; }

    public Element getKxsAt(String attribute) { return this.Kx.get(attribute).duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof CPABEWATERS11SecretKeySerParameter) {
            CPABEWATERS11SecretKeySerParameter that = (CPABEWATERS11SecretKeySerParameter)anObject;
            //Compare K
            if (!PairingUtils.isEqualElement(this.K, that.K)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayK, that.byteArrayK)) {
                return false;
            }
            //Compare L
            if (!PairingUtils.isEqualElement(this.L, that.L)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayL, that.byteArrayL)) {
                return false;
            }
            //compare Kx
            if (!this.Kx.equals(that.Kx)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrayMaps(this.byteArraysKx, that.byteArraysKx)) {
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
        this.K = pairing.getG2().newElementFromBytes(this.byteArrayK);
        this.L = pairing.getG2().newElementFromBytes(this.byteArrayL);
        this.Kx = new HashMap<String, Element>();
        for (String attribute : this.byteArraysKx.keySet()) {
            this.Kx.put(attribute, pairing.getG1().newElementFromBytes(this.byteArraysKx.get(attribute)).getImmutable());
        }
    }
}