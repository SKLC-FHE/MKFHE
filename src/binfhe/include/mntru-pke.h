
#ifndef _MNTRU_PKE_H_
#define _MNTRU_PKE_H_

#include "binfhe-constants.h"
#include "mntru-ciphertext.h"
#include "mntru-keyswitchkey.h"
#include "mntru-keyswitchkey2.h"
#include "mntru-privatekey.h"
// #include "mntru-publickey.h"
// #include "mntru-keypair.h"
#include "mntru-cryptoparameters.h"


//
#include <NTL/ZZ_pX.h>
#include <NTL/mat_ZZ_p.h>
#include <NTL/mat_ZZ.h>

#include <memory>
//
using namespace NTL;
using namespace std;
namespace lbcrypto {


/**
 * @brief Additive public-key MNTRU scheme
 */
class MNTRUEncryptionScheme {
    NativeInteger RoundqQ(const NativeInteger& v, const NativeInteger& q, const NativeInteger& Q) const;

public:
    MNTRUEncryptionScheme() = default;

    void Get_invertible_Matrix(std::vector<NativeVector>& NatMat, std::vector<NativeVector>& NatMat_inv, uint32_t q_base, uint32_t N,SecretKeyDist keyDist) const;
    void Get_MatrixA(std::vector<NativeVector>& MatrixA, NativeVector s) const;
   
    std::vector<NativeVector> MatrixMultiply(const std::vector<NativeVector>& A, const std::vector<NativeVector>& B,NativeInteger mod) const;
   
   
    MNTRUPrivateKey KeyGen(uint32_t k, usint size, const NativeInteger& modulus) const;

    MNTRUPrivateKey KeyGenGaussian(uint32_t k, usint size, const NativeInteger& modulus) const;

    MNTRUCiphertext Encrypt(const std::shared_ptr<MNTRUCryptoParams>& params, ConstMNTRUPrivateKey& sk, MNTRUPlaintext m, MNTRUPlaintextModulus p = 4,NativeInteger mod = 0) const;

    void Decrypt2(const std::shared_ptr<MNTRUCryptoParams>& params, ConstMNTRUPrivateKey& sk, ConstMNTRUCiphertext& ct,MNTRUPlaintext* result, MNTRUPlaintextModulus p = 4) const;

    void DecryptNAND(const std::shared_ptr<MNTRUCryptoParams>& params, ConstMNTRUPrivateKey& sk, ConstMNTRUCiphertext& ct,MNTRUPlaintext* result, MNTRUPlaintextModulus p = 4) const;

    void Decrypt(const std::shared_ptr<MNTRUCryptoParams>& params, ConstMNTRUPrivateKey& sk, ConstMNTRUCiphertext& ct,MNTRUPlaintext* result, MNTRUPlaintextModulus p = 4) const;


    MNTRUCiphertext ModSwitch(NativeInteger q, ConstMNTRUCiphertext& ctQ) const;


    void mod_q(NativeVector& output, std::vector<long>& input,const long q) const;

    MNTRUSwitchingKey KeySwitchGen(const std::shared_ptr<MNTRUCryptoParams>& params, ConstMNTRUPrivateKey& sk, const std::vector<NativeVector> skN) const;

    MNTRUCiphertext KeySwitch(const std::shared_ptr<MNTRUCryptoParams>& params, ConstMNTRUSwitchingKey& K,
                            ConstMNTRUCiphertext& ctQN) const;

    MNTRUSwitchingKey2 KeySwitchGen2(const std::shared_ptr<MNTRUCryptoParams>& params, ConstMNTRUPrivateKey& sk, const std::vector<NativeVector> skN) const;

    MNTRUCiphertext KeySwitch2(const std::shared_ptr<MNTRUCryptoParams>& params, ConstMNTRUSwitchingKey2& K,
                            ConstMNTRUCiphertext& ctQN) const;



    void EvalSubEq(MNTRUCiphertext& ct1, ConstMNTRUCiphertext& ct2) const;

    void EvalAddEq(MNTRUCiphertext& ct1, ConstMNTRUCiphertext& ct2) const;


};

}  // namespace lbcrypto

#endif
