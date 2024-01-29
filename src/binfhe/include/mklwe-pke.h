
#ifndef _MKLWE_PKE_H_
#define _MKLWE_PKE_H_

#include "binfhe-constants.h"
#include "mklwe-ciphertext.h"
#include "mklwe-keyswitchkey.h"
#include "mklwe-privatekey.h"
// #include "mklwe-publickey.h"
// #include "mklwe-keypair.h"
#include "mklwe-cryptoparameters.h"

#include <memory>

namespace lbcrypto {

/**
 * @brief Additive public-key MKLWE scheme
 */
class MKLWEEncryptionScheme {
    NativeInteger RoundqQ(const NativeInteger& v, const NativeInteger& q, const NativeInteger& Q) const;

public:
    MKLWEEncryptionScheme() = default;


    MKLWEPrivateKey KeyGenBinary(usint k,usint size, const NativeInteger& modulus) const;

    MKLWECiphertext Encrypt(const std::shared_ptr<MKLWECryptoParams>& params, ConstMKLWEPrivateKey& sk, MKLWEPlaintext m,
                          MKLWEPlaintextModulus p = 4, NativeInteger mod = 0) const;
    
    void Decrypt(const std::shared_ptr<MKLWECryptoParams>& params, ConstMKLWEPrivateKey& sk, ConstMKLWECiphertext& ct,
                 MKLWEPlaintext* result, MKLWEPlaintextModulus p = 4) const;

    void DecryptNAND(const std::shared_ptr<MKLWECryptoParams>& params, ConstMKLWEPrivateKey& sk, ConstMKLWECiphertext& ct,
                 MKLWEPlaintext* result, MKLWEPlaintextModulus p = 4) const;


    void EvalAddEq(MKLWECiphertext& ct1, ConstMKLWECiphertext& ct2) const;

    void EvalAddConstEq(MKLWECiphertext& ct, NativeInteger cnst) const;

   
    void EvalSubEq(MKLWECiphertext& ct1, ConstMKLWECiphertext& ct2) const;

   
    void EvalSubEq2(ConstMKLWECiphertext& ct1, MKLWECiphertext& ct2) const;

    void EvalSubConstEq(MKLWECiphertext& ct, NativeInteger cnst) const;

   
    void EvalMultConstEq(MKLWECiphertext& ct, NativeInteger cnst) const;

    MKLWECiphertext ModSwitch(NativeInteger q, ConstMKLWECiphertext& ctQ) const;


    MKLWESwitchingKey KeySwitchGen(const std::shared_ptr<MKLWECryptoParams>& params, ConstMKLWEPrivateKey& sk,
                                 std::vector<NativeVector>& skN) const;

    MKLWECiphertext KeySwitch(const std::shared_ptr<MKLWECryptoParams>& params, ConstMKLWESwitchingKey& K,
                            ConstMKLWECiphertext& ctQN) const;




    
    MKLWECiphertext NoiselessEmbedding(const std::shared_ptr<MKLWECryptoParams>& params, MKLWEPlaintext m) const;
};

}  // namespace lbcrypto

#endif
