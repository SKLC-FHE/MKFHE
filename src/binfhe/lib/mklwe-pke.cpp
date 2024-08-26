

#include "mklwe-pke.h"

#include "math/binaryuniformgenerator.h"
#include "math/discreteuniformgenerator.h"
#include "math/ternaryuniformgenerator.h"
//#define WITH_NOISE_DEBUG
using namespace std;
namespace lbcrypto {

NativeInteger MKLWEEncryptionScheme::RoundqQ(const NativeInteger& v, const NativeInteger& q,
                                           const NativeInteger& Q) const {
    return NativeInteger(static_cast<BasicInteger>(
                             std::floor(0.5 + v.ConvertToDouble() * q.ConvertToDouble() / Q.ConvertToDouble())))
        .Mod(q);
}

MKLWEPrivateKey MKLWEEncryptionScheme::KeyGenBinary(usint k,usint size, const NativeInteger& modulus) const {
    // cout<<"In MKLWEEncryptionScheme KeyGenBinary"<<endl;
    BinaryUniformGeneratorImpl<NativeVector> bug;
    std::vector<NativeVector> sk;
    auto bsk = bug.GenerateVector(size, modulus);
    // cout<<bsk<<endl;
    for(uint32_t u=0;u<k;u++)
    {
        sk.push_back(bug.GenerateVector(size, modulus));
    }
    return std::make_shared<MKLWEPrivateKeyImpl>(MKLWEPrivateKeyImpl(sk));
}


// classical MKLWE encryption
// a is a randomly uniform vector of dimension n; with integers mod q
// b = a*s + e + m floor(q/4) is an integer mod q
MKLWECiphertext MKLWEEncryptionScheme::Encrypt(const std::shared_ptr<MKLWECryptoParams>& params, ConstMKLWEPrivateKey& sk,
                                           MKLWEPlaintext m, MKLWEPlaintextModulus p, NativeInteger mod) const {
    if (mod % p != 0 && mod.ConvertToInt() & (1 == 0)) {
        std::string errMsg = "ERROR: ciphertext modulus q needs to be divisible by plaintext modulus p.";
        OPENFHE_THROW(not_implemented_error, errMsg);
    }

    std::vector<NativeVector> s = sk->GetElement();
    uint32_t n     = params->Getn();
    auto k = params->Getk();
    auto err = params->GetDgg().GenerateInteger(mod);
    // cout<<"err = "<<err<<endl;
    NativeInteger b = (m % p) * (mod / p) + err;
    std::vector<NativeVector> a(k,NativeVector(n,mod));
    for(uint32_t u = 0 ; u<k ;u++)
    {
        s[u].SwitchModulus(mod);

      DiscreteGaussianGeneratorImpl<NativeVector> dgg;
        a[u] = dgg.GenerateVector(n,mod);
        NativeInteger mu = mod.ComputeMu();
        for (size_t i = 0; i < n; ++i) {
            b += a[u][i].ModMulFast(s[u][i], mod, mu);
        }
    }
    auto ct = std::make_shared<MKLWECiphertextImpl>(MKLWECiphertextImpl(std::move(a), b.Mod(mod)));
    ct->SetptModulus(p);
    return ct;
}

void MKLWEEncryptionScheme::Decrypt(const std::shared_ptr<MKLWECryptoParams>& params, ConstMKLWEPrivateKey& sk,
                                  ConstMKLWECiphertext& ct, MKLWEPlaintext* result, MKLWEPlaintextModulus p) const {

    const NativeInteger& mod = ct->GetModulus();
    if (mod % (p * 2) != 0 && mod.ConvertToInt() & (1 == 0)) {
        std::string errMsg = "ERROR: ciphertext modulus q needs to be divisible by plaintext modulus p*2.";
        OPENFHE_THROW(not_implemented_error, errMsg);
    }

    std::vector<NativeVector> a   = ct->GetA();
    std::vector<NativeVector> s   = sk->GetElement();
    uint32_t n       = params->Getn();
    NativeInteger mu = mod.ComputeMu();
    uint32_t k =params->Getk();
    NativeInteger inner(0);
    for(uint32_t u=0;u<k;u++)
    {
        s[u].SwitchModulus(mod);
        for (size_t i = 0; i < n; ++i) {
        inner += a[u][i].ModMulFast(s[u][i], mod, mu);
        }
        inner.ModEq(mod);
    }
    NativeInteger r = ct->GetB();

    r.ModSubFastEq(inner, mod);//b-as
    // cout<<"b-as  = "<<r<<endl;


    r.ModAddFastEq((mod / (p * 2)), mod);

    *result = ((NativeInteger(p) * r) / mod).ConvertToInt();

#if defined(WITH_NOISE_DEBUG)
    
    int q = ct->GetModulus().ConvertToInt();

    NativeInteger temp = r.ModSubFastEq((mod / (p * 2)), mod);
    NativeInteger ans =  typename NativeVector::Integer(1);
    temp.ModSubFastEq(NativeVector::Integer(ans * mod / 4), mod); 
    int err = temp.ConvertToInt();
    if (err > (q / 2)) {
        err = err - q;
    }
    std::cerr << err <<",";
#endif
}


void MKLWEEncryptionScheme::DecryptNAND(const std::shared_ptr<MKLWECryptoParams>& params, ConstMKLWEPrivateKey& sk,
                                  ConstMKLWECiphertext& ct, MKLWEPlaintext* result, MKLWEPlaintextModulus p) const {
    // TODO in the future we should add a check to make sure sk parameters match
    // the ct parameters

    // Create local variables to speed up the computations
    const NativeInteger& mod = ct->GetModulus();
    if (mod % (p/2 * 2) != 0 && mod.ConvertToInt() & (1 == 0)) {
        std::string errMsg = "ERROR: ciphertext modulus q needs to be divisible by plaintext modulus p*2.";
        OPENFHE_THROW(not_implemented_error, errMsg);
    }

    std::vector<NativeVector> a   = ct->GetA();
    std::vector<NativeVector> s   = sk->GetElement();
    uint32_t n       = params->Getn();
    NativeInteger mu = mod.ComputeMu();
    uint32_t k =params->Getk();
    NativeInteger inner(0);
    for(uint32_t u=0;u<k;u++)
    {
        s[u].SwitchModulus(mod);
        for (size_t i = 0; i < n; ++i) {
        inner += a[u][i].ModMulFast(s[u][i], mod, mu);
        }
        inner.ModEq(mod);
    }
    NativeInteger r = ct->GetB();

    r.ModSubFastEq(inner, mod);//b-as
     cout<<"b-as"<<inner<<endl;

    r.ModAddFastEq((mod / (p)), mod);

    *result = ((NativeInteger(p/2) * r) / mod).ConvertToInt();

#if defined(WITH_NOISE_DEBUG)
    double error =
        (static_cast<double>(p/2) * (r.ConvertToDouble() - mod.ConvertToDouble() / (p))) / mod.ConvertToDouble() -
        static_cast<double>(*result);
    std::cerr << error * mod.ConvertToDouble() / static_cast<double>(p) << std::endl;
#endif
}


// Modulus switching - directly applies the scale-and-round operation RoundQ
MKLWECiphertext MKLWEEncryptionScheme::ModSwitch(NativeInteger q, ConstMKLWECiphertext& ctQ) const {
    auto n = ctQ->GetLength();
    auto Q = ctQ->GetModulus();
    auto k = ctQ->Getk();
    std::vector<NativeVector> a(k,NativeVector(n, q));
    for(uint32_t u = 0; u<k ; u++){
        for (size_t i = 0; i < n; ++i){
            a[u][i] = RoundqQ(ctQ->GetA()[u][i], q, Q);
        }
    }
    return std::make_shared<MKLWECiphertextImpl>(MKLWECiphertextImpl(std::move(a), RoundqQ(ctQ->GetB(), q, Q)));
}



// Switching key as described in Section 3 of https://eprint.iacr.org/2014/816
MKLWESwitchingKey MKLWEEncryptionScheme::KeySwitchGen(const std::shared_ptr<MKLWECryptoParams>& params,
                                                  ConstMKLWEPrivateKey& sk, std::vector<NativeVector>& skN) const {
    const size_t n(params->Getn());
    const size_t N(params->GetN());
    NativeInteger qKS(params->GetqKS());
    NativeInteger::Integer value{1};
    NativeInteger::Integer baseKS(params->GetBaseKS());
    const auto digitCount =
        static_cast<size_t>(std::ceil(log(qKS.ConvertToDouble()) / log(static_cast<double>(baseKS))));
    std::vector<NativeInteger> digitsKS;
    digitsKS.reserve(digitCount);
    for (size_t i = 0; i < digitCount; ++i) {
        digitsKS.emplace_back(value);
        value *= baseKS;
    }
    auto usrnum(params->Getk());
    std::vector<std::vector<std::vector<std::vector<NativeVector>>>> resultVecA(usrnum,std::vector<std::vector<std::vector<NativeVector>>>(N));
    std::vector<std::vector<std::vector<std::vector<NativeInteger>>>> resultVecB(usrnum,std::vector<std::vector<std::vector<NativeInteger>>>(N));
    // std::vector<std::vector<std::vector<std::vector<NativeInteger>>>> resultVecB(usrnum,std::vector<std::vector<std::vector<NativeInteger>>>(N,std::vector<std::vector<NativeInteger>>(baseKS,std::vector<NativeInteger>(digitCount))));

    // std::vector<std::vector<std::vector<NativeInteger>>> resultVecBsum(N);
    for(uint32_t u=0;u<usrnum;u++)
    {
        NativeVector sv(sk->GetElement()[u]);
        sv.SwitchModulus(qKS);
        NativeVector svN = skN[u];
        svN.SwitchModulus(qKS);
        // DiscreteUniformGeneratorImpl<NativeVector> dug;
        // dug.SetModulus(qKS);
        auto dgg= params->GetDgg();
        NativeInteger mu(qKS.ComputeMu());
        for (size_t i = 0; i < N; ++i) {
            std::vector<std::vector<NativeVector>> vector1A;
            vector1A.reserve(baseKS);
            std::vector<std::vector<NativeInteger>> vector1B;
            vector1B.reserve(baseKS);

            for (size_t j = 0; j < baseKS; ++j) {//Bks
                std::vector<NativeVector> vector2A;
                vector2A.reserve(digitCount);
                std::vector<NativeInteger> vector2B;
                vector2B.reserve(digitCount);
                for (size_t k = 0; k < digitCount; ++k) {//dks
                  //  vector2A.emplace_back(dug.GenerateVector(n));
                    vector2A.emplace_back(dgg.GenerateVector(n,qKS));
                  //  cout<<vector2A[k]<<endl;
                    NativeVector& a = vector2A.back();
                    NativeInteger b = (params->GetDggKS().GenerateInteger(qKS)).ModAdd(svN[i].ModMul(j * digitsKS[k], qKS), qKS);
    #if NATIVEINT == 32
                    for (size_t i = 0; i < n; ++i) {
                        b.ModAddFastEq(a[i].ModMulFast(sv[i], qKS, mu), qKS);
                    }
    #else
                    for (size_t i = 0; i < n; ++i) {//n
                        b += a[i].ModMulFast(sv[i], qKS, mu);
                    }
                    b.ModEq(qKS);
    #endif
                    vector2B.emplace_back(b);
                }
                vector1A.push_back(std::move(vector2A));
                vector1B.push_back(std::move(vector2B));
            }
            resultVecA[u][i] = std::move(vector1A);
            resultVecB[u][i] = std::move(vector1B);
        }
    }
    
    // for(size_t i = 0; i < N; ++i){
    //     for(size_t j = 0; j < baseKS; ++j){
    //         for (size_t k = 0; k < digitCount; ++k){
    //             for(uint32_t u=0;u<usrnum;u++){
    //                 resultVecBsum[i][j][k].ModAddEq(resultVecB[u][i][j][k],qKS);
    //             }
    //         }
    //     }
    // }
    

    return std::make_shared<MKLWESwitchingKeyImpl>(MKLWESwitchingKeyImpl(std::move(resultVecA), std::move(resultVecB)));
}



MKLWECiphertext MKLWEEncryptionScheme::KeySwitch(const std::shared_ptr<MKLWECryptoParams>& params, ConstMKLWESwitchingKey& K,
                            ConstMKLWECiphertext& ctQN) const{

    const size_t n(params->Getn());
    const size_t N(params->GetN());
    NativeInteger Q(params->GetqKS());
    const auto k(params->Getk());
    NativeInteger::Integer baseKS(params->GetBaseKS());
    const auto digitCount = static_cast<size_t>(std::ceil(log(Q.ConvertToDouble()) / log(static_cast<double>(baseKS))));

    
    std::vector<NativeVector> a(k,NativeVector(n, Q));
    NativeInteger b(ctQN->GetB());
    for(uint32_t u=0;u<k;u++){
        for (size_t i = 0; i < N; ++i) {
            auto& refA = K->GetElementsA()[u][i];
            auto& refB = K->GetElementsB()[u][i];
            NativeInteger::Integer atmp(ctQN->GetA(u,i).ConvertToInt());
            for (size_t j = 0; j < digitCount; ++j) {
                const auto a0 = (atmp % baseKS);
                atmp /= baseKS;
                b.ModSubFastEq(refB[a0][j], Q);
                auto& refAj = refA[a0][j];
                for (size_t l = 0; l < n; ++l)
                    a[u][l].ModSubFastEq(refAj[l], Q);
            }
        }
    }

    return std::make_shared<MKLWECiphertextImpl>(MKLWECiphertextImpl(std::move(a), b));
}









void MKLWEEncryptionScheme::EvalAddEq(MKLWECiphertext& ct1, ConstMKLWECiphertext& ct2) const {
    uint32_t k = ct1->Getk();
    for(uint32_t u=0;u<k;u++)
    {
        ct1->GetA()[u].ModAddEq(ct2->GetA()[u]);
    }
    ct1->GetB().ModAddFastEq(ct2->GetB(), ct1->GetModulus());
}



void MKLWEEncryptionScheme::EvalSubEq(MKLWECiphertext& ct1, ConstMKLWECiphertext& ct2) const {
    uint32_t k = ct1->Getk();
    for(uint32_t u=0;u<k;u++)
    {
        ct1->GetA()[u].ModSubEq(ct2->GetA()[u]);
    }
    ct1->GetB().ModSubFastEq(ct2->GetB(), ct1->GetModulus());
}


};  // namespace lbcrypto
