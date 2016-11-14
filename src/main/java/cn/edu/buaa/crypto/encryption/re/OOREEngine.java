package cn.edu.buaa.crypto.encryption.re;

import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.genparams.PairingKeyEncapsulationSerPair;

/**
 * Created by Weiran Liu on 2016/4/5.
 *
 * Generic Online/Offline Revocation Encryption engine.
 */
public interface OOREEngine extends REEngine {
    /**
     * Offline Key Encapsulation Algorithm for RE
     * @param publicKey public key
     * @param n number of revocation identity set
     * @return session key / offline ciphertext pair associated with n
     */
    PairingKeyEncapsulationSerPair offlineEncapsulation(AsymmetricKeySerParameter publicKey, int n);

    /**
     * Online Key Encapsulation Algorithm for RE
     * @param publicKey public key
     * @param ids revocation identity set
     * @return session key / ciphertext pair associated with the revocation identity set
     */
    PairingKeyEncapsulationSerPair onlineEncapsulation(AsymmetricKeySerParameter publicKey, PairingCipherSerParameter iCiphertext, String... ids);
}
