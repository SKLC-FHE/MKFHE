
#include "binfhecontext.h"
#include <string>
#include <unordered_map>

namespace lbcrypto {

void BinFHEContext::GenerateBinFHEContext(uint32_t n, uint32_t N, const NativeInteger& q, const NativeInteger& Q,
                                          double std, uint32_t baseKS, uint32_t baseG, uint32_t baseR,
                                          SecretKeyDist keyDist, BINFHE_METHOD method, uint32_t numAutoKeys) {

    auto lweparams = std::make_shared<LWECryptoParams>(n, N, q, Q, Q, std, baseKS);
    auto rgswparams =
        std::make_shared<RingGSWCryptoParams>(N, Q, q, baseG, baseR, method, std, keyDist, true, numAutoKeys);
    m_params       = std::make_shared<BinFHECryptoParams>(lweparams, rgswparams);
    m_binfhescheme = std::make_shared<BinFHEScheme>(method);
}

void BinFHEContext::GenerateBinFHEContext(BINFHE_PARAMSET set, bool arbFunc, uint32_t logQ, int64_t N,
                                          BINFHE_METHOD method, bool timeOptimization) {
    if (GINX != method) {
        std::string errMsg("ERROR: CGGI is the only supported method");
        OPENFHE_THROW(not_implemented_error, errMsg);
    }
    if (set != STD128 && set != TOY) {
        std::string errMsg("ERROR: STD128 and TOY are the only supported sets");
        OPENFHE_THROW(not_implemented_error, errMsg);
    }

    if (logQ > 29) {
        std::string errMsg("ERROR: logQ > 29 is not supported");
        OPENFHE_THROW(not_implemented_error, errMsg);
    }
    if (logQ < 11) {
        std::string errMsg("ERROR: logQ < 11 is not supported");
        OPENFHE_THROW(not_implemented_error, errMsg);
    }
    auto logQprime = 54;
    uint32_t baseG = 0;
    if (logQ > 25) {
        baseG = 1 << 14;
    }
    else if (logQ > 16) {
        baseG = 1 << 18;
    }
    else if (logQ > 11) {
        baseG = 1 << 27;
    }
    else {  // if (logQ == 11)
        baseG     = 1 << 5;
        logQprime = 27;
    }

    m_timeOptimization = timeOptimization;
    SecurityLevel sl   = HEStd_128_classic;
    // choose minimum ringD satisfying sl and Q
    uint32_t ringDim = StdLatticeParm::FindRingDim(HEStd_ternary, sl, logQprime);
    if (N >= ringDim) {  // if specified some larger N, security is also satisfied
        ringDim = N;
    }
    // find prime Q for NTT
    NativeInteger Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(logQprime, 2 * ringDim), 2 * ringDim);
    // q = 2*ringDim by default for maximum plaintext space, if needed for arbitrary function evaluation, q = ringDim
    uint32_t q = arbFunc ? ringDim : 2 * ringDim;

    uint64_t qKS = 1 << 30;
    qKS <<= 5;

    uint32_t n      = (set == TOY) ? 32 : 1305;
    auto lweparams  = std::make_shared<LWECryptoParams>(n, ringDim, q, Q, qKS, 3.19, 32);
    auto rgswparams = std::make_shared<RingGSWCryptoParams>(ringDim, Q, q, baseG, 23, method, 3.19, UNIFORM_TERNARY,
                                                            ((logQ != 11) && timeOptimization));

    m_params       = std::make_shared<BinFHECryptoParams>(lweparams, rgswparams);
    m_binfhescheme = std::make_shared<BinFHEScheme>(method);

#if defined(BINFHE_DEBUG)
    std::cout << ringDim << " " << Q < < < < " " << n << " " << q << " " << baseG << std::endl;
#endif
}


void BinFHEContext::GenerateBinFHEContext(BINFHE_PARAMSET set, BINFHE_METHOD method) {
    enum { PRIME = 0 };  // value for modKS if you want to use the intermediate prime for modulus for key switching
    constexpr double STD_DEV  = 1.9;
    constexpr double STD_NTRU = 0.5;
    constexpr double STD_NTRU2 = 0.75;
    // clang-format off


    const std::unordered_map<BINFHE_PARAMSET, BinFHEContextParams> paramsMap
    ({
        //               numUser|numberBits|cyclOrder|latticeParam|  mod|   modKS|  stdDev| baseKS| gadgetBase| baseRK| numAutoKeys| keyDist
        { TOY,               { 1,        27,     1024,          64,  512,   PRIME, STD_DEV,     25,    1 <<  9,  23,     9,  UNIFORM_TERNARY} },
        { MEDIUM,            { 1,        28,     2048,         422, 1024, 1 << 14, STD_DEV, 1 << 7,    1 << 10,  32,    10,  UNIFORM_TERNARY} },
        { STD192,            { 1,        37,     4096,         805, 1024, 1 << 15, STD_DEV,     32,    1 << 13,  32,    10,  UNIFORM_TERNARY} },
        { STD256,            { 1,        29,     4096,         990, 2048, 1 << 14, STD_DEV, 1 << 7,    1 <<  8,  46,    10,  UNIFORM_TERNARY} },
        { STD128Q,           { 1,        25,     2048,         534, 1024, 1 << 14, STD_DEV,     32,    1 <<  7,  32,    10,  UNIFORM_TERNARY} },
        { STD128Q_LMKCDEY,   { 1,        27,     2048,         448, 1024, 1 << 13, STD_DEV,     32,    1 <<  9,  32,    10,  GAUSSIAN       } },
        { STD192Q,           { 1,        35,     4096,         875, 1024, 1 << 15, STD_DEV,     32,    1 << 12,  32,    10,  UNIFORM_TERNARY} },
        { STD256Q,           { 1,        27,     4096,        1225, 1024, 1 << 16, STD_DEV,     16,    1 <<  7,  32,    10,  UNIFORM_TERNARY} },
        { STD128_3,          { 1,        27,     2048,         541, 1024, 1 << 15, STD_DEV,     32,    1 <<  7,  32,    10,  UNIFORM_TERNARY} },
        { STD128_3_LMKCDEY,  { 1,        28,     2048,         485, 1024, 1 << 15, STD_DEV,     32,    1 << 10,  32,    10,  GAUSSIAN       } },
        { STD128Q_3_LMKCDEY, { 1,        27,     2048,         524, 1024, 1 << 15, STD_DEV,     32,    1 <<  9,  32,    10,  GAUSSIAN       } },
        { STD192Q_3,         { 1,        34,     4096,         922, 2048, 1 << 16, STD_DEV,     16,    1 << 12,  32,    10,  UNIFORM_TERNARY} },
        { STD256Q_3,         { 1,        27,     4096,        1400, 4096, 1 << 16, STD_DEV,     21,    1 <<  6,  32,    10,  UNIFORM_TERNARY} },
        { STD128_4,          { 1,        27,     2048,         541, 2048, 1 << 15, STD_DEV,     32,    1 <<  7,  32,    10,  UNIFORM_TERNARY} },
        { STD128_4_LMKCDEY,  { 1,        28,     2048,         522, 2048, 1 << 15, STD_DEV,     32,    1 << 10,  32,    10,  GAUSSIAN       } },
        { STD128Q_4,         { 1,        50,     4096,         647, 2048, 1 << 16, STD_DEV,     16,    1 << 25,  32,    10,  UNIFORM_TERNARY} },
        { STD128Q_4_LMKCDEY, { 1,        27,     2048,         524, 2048, 1 << 15, STD_DEV,     32,    1 <<  7,  32,    10,  GAUSSIAN       } },
        { STD192Q_4,         { 1,        34,     4096,         980, 2048, 1 << 17, STD_DEV,     16,    1 << 12,  32,    10,  UNIFORM_TERNARY} },
        { STD256Q_4,         { 1,        27,     4096,        1625, 4096, 1 << 21, STD_DEV,     16,    1 <<  6,  32,    10,  UNIFORM_TERNARY} },
        { SIGNED_MOD_TEST,   { 1,        28,     2048,         512, 1024,   PRIME, STD_DEV,     25,    1 <<  7,  23,    10,  UNIFORM_TERNARY} },
        //               numuser|numberBits|cyclOrder|latticeParam|  mod|   modKS|  stdDev| baseKS| gadgetBase| baseRK| numAutoKeys| keyDist
        { STD128_LMKCDEY,    { 1,        28,     2048,         446, 1024, 1 << 13, STD_DEV, 1 << 5,    1 << 10,  32,    10,  GAUSSIAN       } },
        { STD128_LMKCDEY_New,{ 1,        28,     2048,         446, 1024, 1 << 13, STD_DEV, 1 << 5,    1 <<  7,  32,    10,  GAUSSIAN       } },
        { STD128_AP,         { 1,        27,     2048,         503, 1024, 1 << 14, STD_DEV, 1 << 5,    1 <<  9,  32,    10,  UNIFORM_TERNARY} },
        { STD128,            { 1,        27,     2048,         503, 1024, 1 << 14, STD_DEV, 1 << 5,    1 <<  9,  32,    10,  UNIFORM_TERNARY} },
        //               numuser|numberBits|cyclOrder|latticeParam|  mod|   modKS|  stdDev| baseKS| gadgetBase| baseRK| numAutoKeys| keyDist
        { P128T,             { 1,        21,     2048,         512, 1024, 1 << 14, STD_NTRU,    32,    1 <<  7,  32,    10,  UNIFORM_TERNARY} },
        { P128G,             { 1,        21,     2048,         446, 1024, 1 << 14, STD_NTRU,    32,    1 <<  7,  32,    10,  GAUSSIAN       } },
        { P128T_2,           { 1,        21,     2048,         512, 1024, 1 << 14, STD_NTRU,    32,    1 <<  6,  32,    10,  UNIFORM_TERNARY} },
        { P128G_2,           { 1,        21,     2048,         446, 1024, 1 << 14, STD_NTRU,    32,    1 <<  5,  32,    10,  GAUSSIAN       } },
        //               numuser|numberBits|cyclOrder|latticeParam|  mod|   modKS|  stdDev| baseKS| gadgetBase| baseRK| numAutoKeys| keyDist
        { P192T,             { 1,        26,     4096,        1024, 1024, 1 << 17, STD_NTRU,    28,    1 <<  9,  32,    10,  UNIFORM_TERNARY} },
        { P192G,             { 1,        26,     4096,         805, 1024, 1 << 17, STD_NTRU,    28,    1 <<  9,  32,    10,  GAUSSIAN       } },
        //MK-FHE
                             //numuser|numberBits|cyclOrder|latticeParam|  mod|   modKS|  stdDev| baseKS| gadgetBase| baseRK| numAutoKeys| keyDist
     { STD128_MKNTRU,        {2,          27,    4096,             765,     45181,45181,       STD_NTRU ,    32,    1 <<  7,  32,    10,  UNIFORM_TERNARY} },
     { STD128_MKNTRU_2,      {4,          27,    4096,             765,     45181, 45181,      STD_NTRU ,    32,    1 <<  7,  32,    10,  UNIFORM_TERNARY} },
     { STD128_MKNTRU_3,      {8,          27,    4096,             765,     45181, 45181,      STD_NTRU ,    32,    1 <<  6,  32,    10,  UNIFORM_TERNARY} },
     { STD128_MKNTRU_4,      {16,         27,    4096,             765,     45181, 45181,      STD_NTRU,    32,    1 <<  5,  32,    10,  UNIFORM_TERNARY} },
     { STD128_MKNTRU_LWE,    {2,          27,    4096,             635,     32749, 32749,      STD_DEV,    32,    1 << 9 ,  2,    10,  BINARY} },
     { STD128_MKNTRU_LWE_2,  {4,          27,    4096,             635,     32749, 32749,      STD_DEV,    32,    1 << 9 ,  2,    10,  BINARY} },
     { STD128_MKNTRU_LWE_3,  {8,          27,    4096,             635,     32749, 32749,      STD_DEV,    32,    1 << 9,  2,    10,  BINARY} },
     { STD128_MKNTRU_LWE_4,  {16,         27,    4096,             635,     32749, 32749,      STD_DEV,    32,    1 << 7,  2,    10,  BINARY} },
     { STD100_MKNTRU,        {2,           27,    4096,            560,     45181,45181,        STD_NTRU2 ,    32,    1 <<  9,  32,    10,  UNIFORM_TERNARY} },
     { STD100_MKNTRU_2,      {4,          27,     4096,            560,     45181, 45181,       STD_NTRU2,    32,    1 <<  9,  32,    10,  UNIFORM_TERNARY} },
     { STD100_MKNTRU_3,      {8,          27,     4096,            560,     45181, 45181,       STD_NTRU2 ,    32,    1 <<  9,  32,    10,  UNIFORM_TERNARY} },
     { STD100_MKNTRU_4,      {16,         27,     4096,            560,     45181, 45181,       STD_NTRU2,    32,    1 <<  9,  32,    10,  UNIFORM_TERNARY} },
     { STD100_MKNTRU_LWE,    {2,          27,    4096,             500,     32749, 32749,     STD_DEV,    32,    1 << 9 ,  2,    10,  BINARY} },
     { STD100_MKNTRU_LWE_2,  {4,          27,    4096,             500,     32749, 32749,     STD_DEV,    32,    1 << 9 ,  2,    10,  BINARY} },
     { STD100_MKNTRU_LWE_3,  {8,          27,    4096,             500,     32749, 32749,     STD_DEV,    32,    1 << 9,  2,    10,  BINARY} },
     { STD100_MKNTRU_LWE_4,  {16,         27,    4096,             500,     32749, 32749,     STD_DEV,    32,    1 << 9,  2,    10,  BINARY} },
    // { STD128_MKNTRU_LWE_B,{2,        27,    8,          2,     131071, 131071,      0.9 ,    32,    1 <<  7,  32,    10,  UNIFORM_TERNARY} },
    });
    // clang-format on

    auto search = paramsMap.find(set);
    if (paramsMap.end() == search) {
        std::string errMsg("ERROR: Unknown parameter set [" + std::to_string(set) + "] for FHEW.");
        OPENFHE_THROW(config_error, errMsg);
    }

    BinFHEContextParams params = search->second;
    // intermediate prime
    NativeInteger Q(
        PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(params.numberBits, params.cyclOrder), params.cyclOrder));

    usint ringDim  = params.cyclOrder / 2;  //N
    auto lweparams = (PRIME == params.modKS) ?
                         std::make_shared<LWECryptoParams>(params.latticeParam, ringDim, params.mod, Q, Q,
                                                           params.stdDev, params.baseKS, params.keyDist) :
                         std::make_shared<LWECryptoParams>(params.latticeParam, ringDim, params.mod, Q, params.modKS,
                                                           params.stdDev, params.baseKS, params.keyDist);

    auto mntruparams = std::make_shared<MNTRUCryptoParams>(params.numUser, params.latticeParam, ringDim, params.mod, Q,
                                                           params.modKS, params.stdDev, params.baseKS, params.keyDist);

    auto mklweparams = std::make_shared<MKLWECryptoParams>(params.numUser, params.latticeParam, ringDim, params.mod, Q,
                                                           params.modKS, params.stdDev, params.baseKS, params.keyDist);

   
    if (method == MKNTRU || method == MKNTRU_B) {
        auto uniencparams = std::make_shared<UniEncCryptoParams>(
            params.numUser, ringDim, Q, params.mod, params.gadgetBase, params.baseRK, method, params.stdDev,
            params.keyDist, false, params.numAutoKeys);
        m_params = std::make_shared<BinFHECryptoParams>(mntruparams, uniencparams);
    }
    else if (method == MKNTRU_LWE) {
        auto uniencparams = std::make_shared<UniEncCryptoParams>(
            params.numUser, ringDim, Q, params.mod, params.gadgetBase, params.baseRK, method, params.stdDev,
            params.keyDist, false, params.numAutoKeys);
        m_params = std::make_shared<BinFHECryptoParams>(mklweparams, uniencparams);
    }
    else {
        auto rgswparams =
            std::make_shared<RingGSWCryptoParams>(ringDim, Q, params.mod, params.gadgetBase, params.baseRK, method,
                                                  params.stdDev, params.keyDist, false, params.numAutoKeys);
        m_params = std::make_shared<BinFHECryptoParams>(lweparams, rgswparams);
    }  //

    m_binfhescheme = std::make_shared<BinFHEScheme>(method);
}

void BinFHEContext::GenerateBinFHEContext(const BinFHEContextParams& params, BINFHE_METHOD method) {
    enum { PRIME = 0 };  // value for modKS if you want to use the intermediate prime for modulus for key switching
    // intermediate prime
    NativeInteger Q(
        PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(params.numberBits, params.cyclOrder), params.cyclOrder));

    usint ringDim = params.cyclOrder / 2;

    auto lweparams = (PRIME == params.modKS) ?
                         std::make_shared<LWECryptoParams>(params.latticeParam, ringDim, params.mod, Q, Q,
                                                           params.stdDev, params.baseKS, params.keyDist) :
                         std::make_shared<LWECryptoParams>(params.latticeParam, ringDim, params.mod, Q, params.modKS,
                                                           params.stdDev, params.baseKS, params.keyDist);

    auto rgswparams =
        std::make_shared<RingGSWCryptoParams>(ringDim, Q, params.mod, params.gadgetBase, params.baseRK, method,
                                              params.stdDev, params.keyDist, false, params.numAutoKeys);

    m_params       = std::make_shared<BinFHECryptoParams>(lweparams, rgswparams);
    m_binfhescheme = std::make_shared<BinFHEScheme>(method);
}

LWEPrivateKey BinFHEContext::KeyGen() const {
    auto& LWEParams =
        m_params
            ->GetLWEParams();  
    if (LWEParams->GetKeyDist() == GAUSSIAN)
        return m_LWEscheme->KeyGenGaussian(LWEParams->Getn(), LWEParams->GetqKS());
    return m_LWEscheme->KeyGen(LWEParams->Getn(), LWEParams->GetqKS());
}

LWEPrivateKey BinFHEContext::KeyGenN() const {
    auto& LWEParams = m_params->GetLWEParams();
    if (LWEParams->GetKeyDist() == GAUSSIAN)
        return m_LWEscheme->KeyGenGaussian(LWEParams->GetN(), LWEParams->GetQ());
    return m_LWEscheme->KeyGen(LWEParams->GetN(), LWEParams->GetQ());
}

//
MNTRUPrivateKey BinFHEContext::MNTRU_KeyGen() const {
    // cout<<"In binfhecontext MNTRU_KeyGen"<<endl;
    auto& MNTRUParams = m_params->GetMatrixNTRUParams();
    if (MNTRUParams->GetKeyDist() == GAUSSIAN)
        return m_MNTRUscheme->KeyGenGaussian(MNTRUParams->Getk(), MNTRUParams->Getn(), MNTRUParams->GetqKS());
    return m_MNTRUscheme->KeyGen(MNTRUParams->Getk(), MNTRUParams->Getn(), MNTRUParams->GetqKS());
}

//mklwe sk
MKLWEPrivateKey BinFHEContext::MKLWE_KeyGen() const {
    auto& MKLWEParams = m_params->GetMKLWEParams();
    if (MKLWEParams->GetKeyDist() != BINARY)
        OPENFHE_THROW(config_error, "Support BINARY PrivateKey Only");
    return m_MKLWEscheme->KeyGenBinary(MKLWEParams->Getk(), MKLWEParams->Getn(), MKLWEParams->GetqKS());
}

LWEKeyPair BinFHEContext::KeyGenPair() const {
    auto&& LWEParams = m_params->GetLWEParams();
    return m_LWEscheme->KeyGenPair(LWEParams);
}

LWEPublicKey BinFHEContext::PubKeyGen(ConstLWEPrivateKey& sk) const {
    auto&& LWEParams = m_params->GetLWEParams();
    return m_LWEscheme->PubKeyGen(LWEParams, sk);
}

LWECiphertext BinFHEContext::Encrypt(ConstLWEPrivateKey& sk, LWEPlaintext m, BINFHE_OUTPUT output,
                                     LWEPlaintextModulus p, const NativeInteger& mod) const {
    const auto& LWEParams = m_params->GetLWEParams();

    LWECiphertext ct = (mod == 0) ? m_LWEscheme->Encrypt(LWEParams, sk, m, p, LWEParams->Getq()) :
                                    m_LWEscheme->Encrypt(LWEParams, sk, m, p, mod);

    // BINFHE_OUTPUT is kept as it is for backward compatibility but
    // this logic is obsolete now and commented out
    // if ((output != FRESH) && (p == 4)) {
    //    ct = m_binfhescheme->Bootstrap(m_params, m_BTKey, ct);
    //}
    return ct;
}

MKLWECiphertext BinFHEContext::Encrypt(ConstMKLWEPrivateKey& sk, MKLWEPlaintext m, BINFHE_OUTPUT output,
                                       MKLWEPlaintextModulus p, const NativeInteger& mod) const {
    const auto& MKLWEParams = m_params->GetMKLWEParams();
    MKLWECiphertext ct      = (mod == 0) ? m_MKLWEscheme->Encrypt(MKLWEParams, sk, m, p, MKLWEParams->Getq()) :
                                           m_MKLWEscheme->Encrypt(MKLWEParams, sk, m, p, mod);

    return ct;
}

MNTRUCiphertext BinFHEContext::Encrypt(ConstMNTRUPrivateKey& sk, MNTRUPlaintext m, BINFHE_OUTPUT output,
                                       MNTRUPlaintextModulus p, const NativeInteger& mod) const {
    const auto& MNTRUParams = m_params->GetMatrixNTRUParams();

    MNTRUCiphertext ct = (mod == 0) ? m_MNTRUscheme->Encrypt(MNTRUParams, sk, m, p, MNTRUParams->Getq()) :
                                      m_MNTRUscheme->Encrypt(MNTRUParams, sk, m, p, mod);

    return ct;
}

LWECiphertext BinFHEContext::Encrypt(ConstLWEPublicKey& pk, LWEPlaintext m, BINFHE_OUTPUT output, LWEPlaintextModulus p,
                                     const NativeInteger& mod) const {
    const auto& LWEParams = m_params->GetLWEParams();

    LWECiphertext ct = (mod == 0) ? m_LWEscheme->EncryptN(LWEParams, pk, m, p, LWEParams->GetQ()) :
                                    m_LWEscheme->EncryptN(LWEParams, pk, m, p, mod);

    // Switch from ct of modulus Q and dimension N to smaller q and n
    // This is done by default while calling Encrypt but the output could
    // be set to LARGE_DIM to skip this switching
    if (output == SMALL_DIM) {
        LWECiphertext ct1 = SwitchCTtoqn(m_BTKey.KSkey, ct);
        return ct1;
    }
    return ct;
}

LWECiphertext BinFHEContext::SwitchCTtoqn(ConstLWESwitchingKey& ksk, ConstLWECiphertext& ct) const {
    const auto& LWEParams = m_params->GetLWEParams();
    auto Q                = LWEParams->GetQ();
    auto N                = LWEParams->GetN();

    if ((ct->GetLength() != N) && (ct->GetModulus() != Q)) {
        std::string errMsg("ERROR: Ciphertext dimension and modulus are not large N and Q");
        OPENFHE_THROW(config_error, errMsg);
    }

    LWECiphertext ct1 = m_LWEscheme->SwitchCTtoqn(LWEParams, ksk, ct);

    return ct1;
}

void BinFHEContext::Decrypt(ConstLWEPrivateKey& sk, ConstLWECiphertext& ct, LWEPlaintext* result,
                            LWEPlaintextModulus p) const {
    auto&& LWEParams = m_params->GetLWEParams();
    m_LWEscheme->Decrypt(LWEParams, sk, ct, result, p);
}

/*--------------------------wkx mntru ------------------------------------*/
void BinFHEContext::Decrypt(ConstMNTRUPrivateKey& sk, ConstMNTRUCiphertext& ct, MNTRUPlaintext* result,
                            MNTRUPlaintextModulus p) const {
    //std::cout<<"In BinFHEContext Decrypt"<<std::endl;
    auto&& MNTRUParams = m_params->GetMatrixNTRUParams();
    m_MNTRUscheme->Decrypt(MNTRUParams, sk, ct, result, p);
}

void BinFHEContext::DecryptNAND(ConstMNTRUPrivateKey& sk, ConstMNTRUCiphertext& ct, MNTRUPlaintext* result,
                                MNTRUPlaintextModulus p) const {
    //std::cout<<"In BinFHEContext Decrypt"<<std::endl;
    auto&& MNTRUParams = m_params->GetMatrixNTRUParams();
    m_MNTRUscheme->DecryptNAND(MNTRUParams, sk, ct, result, p);
}

void BinFHEContext::Decrypt2(ConstMNTRUPrivateKey& sk, ConstMNTRUCiphertext& ct, MNTRUPlaintext* result,
                             MNTRUPlaintextModulus p) const {
    //std::cout<<"In BinFHEContext Decrypt"<<std::endl;
    auto&& MNTRUParams = m_params->GetMatrixNTRUParams();
    m_MNTRUscheme->Decrypt2(MNTRUParams, sk, ct, result, p);
}


void BinFHEContext::Decrypt(ConstMKLWEPrivateKey& sk, ConstMKLWECiphertext& ct, MKLWEPlaintext* result,
                            MKLWEPlaintextModulus p) const {
    auto&& MKLWEParams = m_params->GetMKLWEParams();
    m_MKLWEscheme->Decrypt(MKLWEParams, sk, ct, result, p);
}
void BinFHEContext::DecryptNAND(ConstMKLWEPrivateKey& sk, ConstMKLWECiphertext& ct, MKLWEPlaintext* result,
                                MKLWEPlaintextModulus p) const {
    auto&& MKLWEParams = m_params->GetMKLWEParams();
    m_MKLWEscheme->DecryptNAND(MKLWEParams, sk, ct, result, p);
}

LWESwitchingKey BinFHEContext::KeySwitchGen(ConstLWEPrivateKey& sk, ConstLWEPrivateKey& skN) const {
    return m_LWEscheme->KeySwitchGen(m_params->GetLWEParams(), sk, skN);
}

MNTRUSwitchingKey BinFHEContext::KeySwitchGen(ConstMNTRUPrivateKey& sk, std::vector<NativeVector>& skN) const {
    return m_MNTRUscheme->KeySwitchGen(m_params->GetMatrixNTRUParams(), sk, skN);
}

void BinFHEContext::BTKeyGen(ConstLWEPrivateKey& sk, KEYGEN_MODE keygenMode) {
    auto& RGSWParams = m_params->GetRingGSWParams();

    auto temp = RGSWParams->GetBaseG();

 
    if (m_timeOptimization) {
        auto gpowermap = RGSWParams->GetGPowerMap();
        for (std::map<uint32_t, std::vector<NativeInteger>>::iterator it = gpowermap.begin(); it != gpowermap.end();
             ++it) {
            RGSWParams->Change_BaseG(it->first);
            m_BTKey_map[it->first] = m_binfhescheme->KeyGen(m_params, sk, keygenMode);
        }
        RGSWParams->Change_BaseG(temp);
    }

    if (m_BTKey_map.size() != 0) {
        m_BTKey = m_BTKey_map[temp];
    }
    else {
        m_BTKey           = m_binfhescheme->KeyGen(m_params, sk, keygenMode);
        m_BTKey_map[temp] = m_BTKey;
    }
}

LWECiphertext BinFHEContext::EvalBinGate(const BINGATE gate, ConstLWECiphertext& ct1, ConstLWECiphertext& ct2) const {
    //std::cout<<"LWECiphertext BinFHEContext::EvalBinGate"<<std::endl;
    auto& VNTRUParams = m_params->GetVectorNTRUParams();

    if (VNTRUParams != nullptr) {  
     
        return m_binfhescheme->EvalBinGate(m_params, gate, m_NBTKey, ct1, ct2);
    }
    else {
        //std::cout<<"EvalBinGate AP or GINX"<<std::endl;
        return m_binfhescheme->EvalBinGate(m_params, gate, m_BTKey, ct1, ct2);
    }
}

//mk mntru
MNTRUCiphertext BinFHEContext::EvalBinGate(const BINGATE gate, ConstMNTRUCiphertext& ct1,
                                           ConstMNTRUCiphertext& ct2) const {
    // std::cout<<"MNTRUCiphertext BinFHEContext::EvalBinGate"<<std::endl;
    return m_binfhescheme->EvalBinGate(m_params, gate, m_MKBTKey, ct1, ct2, m_ctNAND);
}

//mklwe
MKLWECiphertext BinFHEContext::EvalBinGate(const BINGATE gate, ConstMKLWECiphertext& ct1,
                                           ConstMKLWECiphertext& ct2) const {
    // std::cout<<"---MKLWECiphertext BinFHEContext::EvalBinGate---"<<std::endl;
    return m_binfhescheme->EvalBinGate(m_params, gate, m_MKBTKey, ct1, ct2);
}

LWECiphertext BinFHEContext::EvalBinGate(const BINGATE gate, const std::vector<LWECiphertext>& ctvector) const {
    return m_binfhescheme->EvalBinGate(m_params, gate, m_BTKey, ctvector);
}

LWECiphertext BinFHEContext::Bootstrap(ConstLWECiphertext& ct) const {
    return m_binfhescheme->Bootstrap(m_params, m_BTKey, ct);
}

LWECiphertext BinFHEContext::EvalNOT(ConstLWECiphertext& ct) const {
    return m_binfhescheme->EvalNOT(m_params, ct);
}

LWECiphertext BinFHEContext::EvalConstant(bool value) const {
    return m_LWEscheme->NoiselessEmbedding(m_params->GetLWEParams(), value);
}

LWECiphertext BinFHEContext::EvalFunc(ConstLWECiphertext& ct, const std::vector<NativeInteger>& LUT) const {
    return m_binfhescheme->EvalFunc(m_params, m_BTKey, ct, LUT, GetBeta());
}

LWECiphertext BinFHEContext::EvalFloor(ConstLWECiphertext& ct, uint32_t roundbits) const {
    //    auto q = m_params->GetLWEParams()->Getq().ConvertToInt();
    //    if (roundbits != 0) {
    //        NativeInteger newp = this->GetMaxPlaintextSpace();
    //        SetQ(q / newp * (1 << roundbits));
    //    }
    //    SetQ(q);
    //    return res;
    return m_binfhescheme->EvalFloor(m_params, m_BTKey, ct, GetBeta(), roundbits);
}

LWECiphertext BinFHEContext::EvalSign(ConstLWECiphertext& ct, bool schemeSwitch) {
    const auto& params = std::make_shared<BinFHECryptoParams>(*m_params);
    return m_binfhescheme->EvalSign(params, m_BTKey_map, ct, GetBeta(), schemeSwitch);
}

std::vector<LWECiphertext> BinFHEContext::EvalDecomp(ConstLWECiphertext& ct) {
    return m_binfhescheme->EvalDecomp(m_params, m_BTKey_map, ct, GetBeta());
}

std::vector<NativeInteger> BinFHEContext::GenerateLUTviaFunction(NativeInteger (*f)(NativeInteger m, NativeInteger p),
                                                                 NativeInteger p) {
    if (ceil(log2(p.ConvertToInt())) != floor(log2(p.ConvertToInt()))) {
        std::string errMsg("ERROR: Only support plaintext space to be power-of-two.");
        OPENFHE_THROW(not_implemented_error, errMsg);
    }

    NativeInteger q        = GetParams()->GetLWEParams()->Getq();
    NativeInteger interval = q / p;
    NativeInteger outerval = interval;
    usint vecSize          = q.ConvertToInt();
    std::vector<NativeInteger> vec(vecSize);
    for (size_t i = 0; i < vecSize; ++i) {
        auto temp = f(NativeInteger(i) / interval, p);
        if (temp >= p) {
            std::string errMsg("ERROR: input function should output in Z_{p_output}.");
            OPENFHE_THROW(not_implemented_error, errMsg);
        }
        vec[i] = temp * outerval;
    }

    return vec;
}

void BinFHEContext::NBTKeyGen(ConstLWEPrivateKey& sk, KEYGEN_MODE keygenMode) {
    //std::cout<<"xzddf btkeygen in binfhecontext.cpp"<<std::endl;
    auto& VNTRUParams = m_params->GetVectorNTRUParams();

    auto temp = VNTRUParams->GetBaseG();


    if (m_timeOptimization) {
        auto gpowermap = VNTRUParams->GetGPowerMap();
        for (std::map<uint32_t, std::vector<NativeInteger>>::iterator it = gpowermap.begin(); it != gpowermap.end();
             ++it) {
            VNTRUParams->Change_BaseG(it->first);
          
            m_NBTKey_map[it->first] = m_binfhescheme->NKeyGen(m_params, sk, keygenMode);
            // m_NBTKey_map[it->first] = m_binfhescheme->NKeyGen(m_params, sk, keygenMode);
        }
        VNTRUParams->Change_BaseG(temp);
    }

    if (m_NBTKey_map.size() != 0) {
        m_NBTKey = m_NBTKey_map[temp];
    }
    else {
        m_NBTKey           = m_binfhescheme->NKeyGen(m_params, sk, keygenMode);
        m_NBTKey_map[temp] = m_NBTKey;
    }
}

void BinFHEContext::MKBTKeyGen(ConstMNTRUPrivateKey& sk, KEYGEN_MODE keygenMode) {
    //std::cout<<"xzddf btkeygen in binfhecontext.cpp"<<std::endl;
    auto& UniEncParams = m_params->GetUniEncParams();

    auto temp = UniEncParams->GetBaseG();


    if (m_timeOptimization) {
        auto gpowermap = UniEncParams->GetGPowerMap();
        for (std::map<uint32_t, std::vector<NativeInteger>>::iterator it = gpowermap.begin(); it != gpowermap.end();
             ++it) {
            UniEncParams->Change_BaseG(it->first);
            m_MKBTKey_map[it->first] = m_binfhescheme->MKKeyGen(m_params, sk, keygenMode);
        }
        UniEncParams->Change_BaseG(temp);
    }

    if (m_MKBTKey_map.size() != 0) {
        m_MKBTKey = m_MKBTKey_map[temp];
    }
    else {
        m_MKBTKey           = m_binfhescheme->MKKeyGen(m_params, sk, keygenMode);
        m_MKBTKey_map[temp] = m_MKBTKey;
    }
}

void BinFHEContext::MKBTKeyGen(ConstMKLWEPrivateKey& sk, KEYGEN_MODE keygenMode) {
    //std::cout<<"xzddf btkeygen in binfhecontext.cpp"<<std::endl;
    auto& UniEncParams = m_params->GetUniEncParams();

    auto temp = UniEncParams->GetBaseG();


    if (m_timeOptimization) {
        auto gpowermap = UniEncParams->GetGPowerMap();
        for (std::map<uint32_t, std::vector<NativeInteger>>::iterator it = gpowermap.begin(); it != gpowermap.end();
             ++it) {
            UniEncParams->Change_BaseG(it->first);
            m_MKBTKey_map[it->first] = m_binfhescheme->MKKeyGen(m_params, sk, keygenMode);
        }
        UniEncParams->Change_BaseG(temp);
    }

    if (m_MKBTKey_map.size() != 0) {
        m_MKBTKey = m_MKBTKey_map[temp];
    }
    else {
        m_MKBTKey           = m_binfhescheme->MKKeyGen(m_params, sk, keygenMode);
        m_MKBTKey_map[temp] = m_MKBTKey;
    }
}

//
void BinFHEContext::ctGateGen(ConstMNTRUPrivateKey& sk, const BINGATE gate) {
    m_ctNAND = m_binfhescheme->ctGateGen(m_params, sk, gate);
}

}  // namespace lbcrypto
