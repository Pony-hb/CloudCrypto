package cn.edu.buaa.crypto.encryption.abe.cpabe.waters11.serparams;

import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
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
 * Rouselakis-Waters CP-ABE header parameter.
 */
//new CPABEWATERS11HeaderSerParameter(publicKeyParameter.getParameters(), C0, C1s, C2s)
public class CPABEWATERS11HeaderSerParameter extends PairingCipherSerParameter {
    protected final String[] rhos;
    protected transient Element C0;
    protected final byte[] byteArrayC0;

    protected transient Map<String, Element> C1s;
    private final byte[][] byteArraysC1s;

    protected transient Map<String, Element> C2s;
    private final byte[][] byteArraysC2s;


    public CPABEWATERS11HeaderSerParameter(PairingParameters pairingParameters, Element C0,
                                           Map<String, Element> C1s, Map<String, Element> C2s) {
        super(pairingParameters);

        this.rhos = C1s.keySet().toArray(new String[1]);
        this.C0 = C0.getImmutable();
        this.byteArrayC0 = this.C0.toBytes();

        this.C1s = new HashMap<String, Element>();
        this.byteArraysC1s = new byte[this.rhos.length][];
        this.C2s = new HashMap<String, Element>();
        this.byteArraysC2s = new byte[this.rhos.length][];

        for (int i = 0; i < this.rhos.length; i++) {
            Element C1 = C1s.get(this.rhos[i]).duplicate().getImmutable();
            this.C1s.put(this.rhos[i], C1);
            this.byteArraysC1s[i] = C1.toBytes();

            Element C2 = C2s.get(this.rhos[i]).duplicate().getImmutable();
            this.C2s.put(this.rhos[i], C2);
            this.byteArraysC2s[i] = C2.toBytes();

        }
    }

    public Element getC0() { return this.C0.duplicate(); }

    public Map<String, Element> getC1s() { return this.C1s; }

    public Element getC1sAt(String rho) { return this.C1s.get(rho).duplicate(); }

    public Map<String, Element> getC2s() { return this.C2s; }

    public Element getC2sAt(String rho) { return this.C2s.get(rho).duplicate(); }


    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof CPABEWATERS11HeaderSerParameter) {
            CPABEWATERS11HeaderSerParameter that = (CPABEWATERS11HeaderSerParameter)anObject;
            //Compare C0
            if (!PairingUtils.isEqualElement(this.C0, that.C0)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayC0, that.byteArrayC0)) {
                return false;
            }
            //Compare C1s
            if (!this.C1s.equals(that.C1s)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrays(this.byteArraysC1s, that.byteArraysC1s)) {
                return false;
            }
            //Compare C2s
            if (!this.C2s.equals(that.C2s)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrays(this.byteArraysC2s, that.byteArraysC2s)) {
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
        this.C0 = pairing.getG1().newElementFromBytes(this.byteArrayC0).getImmutable();
        this.C1s = new HashMap<String, Element>();
        this.C2s = new HashMap<String, Element>();

        for (int i = 0; i < this.rhos.length; i++) {
            this.C1s.put(this.rhos[i], pairing.getG1().newElementFromBytes(this.byteArraysC1s[i]).getImmutable());
            this.C2s.put(this.rhos[i], pairing.getG2().newElementFromBytes(this.byteArraysC2s[i]).getImmutable());
        }
    }
}