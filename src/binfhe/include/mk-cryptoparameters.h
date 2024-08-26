
#ifndef _MK_CRYPTOPARAMETERS_H_
#define _MK_CRYPTOPARAMETERS_H_

#include "lattice/lat-hal.h"
#include "math/discretegaussiangenerator.h"
#include "math/nbtheory.h"
#include "utils/serializable.h"
#include "utils/utilities.h"

#include "binfhe-constants.h"

#include "lwe-ciphertext.h"
#include "lwe-keyswitchkey.h"
#include "lwe-cryptoparameters.h"

//
#include "mntru-ciphertext.h"
#include "mntru-keyswitchkey.h"
#include "mntru-cryptoparameters.h"




#include <memory>
#include <string>
#include <utility>
#include <vector>
#include <map>

namespace lbcrypto {

/**
 * @brief Class that stores all parameters for the UniEnc scheme used in
 * bootstrapping
 */
class UniEncCryptoParams : public Serializable {

private:
 
    uint32_t m_k{};



    // Modulus for the UniEnc/RingLWE scheme
    NativeInteger m_Q{};

   
    // Modulus for the RingLWE scheme
    NativeInteger m_q{};

   
    // Ring dimension for the UniEnc/RingLWE scheme
    uint32_t m_N{};

 
    // Gadget base used in bootstrapping
    uint32_t m_baseG{};


    // Base used for the refreshing key (used only for DM bootstrapping)
    uint32_t m_baseR{};

 
    // Number of digits in decomposing integers mod Q
    uint32_t m_digitsG{};


    // Powers of m_baseR (used only for DM bootstrapping)
    std::vector<NativeInteger> m_digitsR;

    // A vector of powers of baseG
    std::vector<NativeInteger> m_Gpower;


    // A vector of log by generator g (=5) (only for LMKCDEY)
    // Not exactly log, but a mapping similar to logarithm for efficiency
    // m_logGen[5^i (mod M)] = i (i > 0)
    // m_logGen[-5^i (mod M)] = -i ()
    // m_logGen[1] = 0
    // m_logGen[-1 (mod M)] = M (special case for efficiency)
    std::vector<int32_t> m_logGen;


    // Error distribution generator
    DiscreteGaussianGeneratorImpl<NativeVector> m_dgg;


    // A map of vectors of powers of baseG for sign evaluation
    std::map<uint32_t, std::vector<NativeInteger>> m_Gpower_map;


    // Parameters for polynomials in UniEnc/RingLWE
    std::shared_ptr<ILNativeParams> m_polyParams;


    // Constants used in evaluating binary gates
    std::vector<NativeInteger> m_gateConst;


    // Precomputed polynomials in Format::EVALUATION representation for X^m - 1
    // (used only for CGGI bootstrapping)
    std::vector<NativePoly> m_monomials;


    // Bootstrapping method (DM or CGGI or LMKCDEY)
    BINFHE_METHOD m_method{BINFHE_METHOD::INVALID_METHOD};

    
    // Secret key distribution: GAUSSIAN, UNIFORM_TERNARY, etc.
    SecretKeyDist m_keyDist{SecretKeyDist::UNIFORM_TERNARY};


    // Number of automorphism keys (used only for LMKCDEY bootstrapping)
    uint32_t m_numAutoKeys{};

    std::vector<NativePoly> m_CRS{};


public:
    UniEncCryptoParams() = default;


    explicit UniEncCryptoParams(uint32_t k,uint32_t N, NativeInteger Q, NativeInteger q, uint32_t baseG, uint32_t baseR,
                                 BINFHE_METHOD method, double std, SecretKeyDist keyDist = UNIFORM_TERNARY,
                                 bool signEval = false, uint32_t numAutoKeys = 10)
        : m_k(k),
          m_Q(Q),
          m_q(q),
          m_N(N),
          m_baseG(baseG),
          m_baseR(baseR),
          m_polyParams{std::make_shared<ILNativeParams>(2 * N, Q)},
          m_method(method),
          m_keyDist(keyDist),
          m_numAutoKeys(numAutoKeys) {
        if (!IsPowerOfTwo(baseG))
            OPENFHE_THROW(config_error, "Gadget base should be a power of two.");
        if ((method == LMKCDEY) & (numAutoKeys == 0))
            OPENFHE_THROW(config_error, "numAutoKeys should be greater than 0.");
        auto logQ{log(m_Q.ConvertToDouble())};
        m_digitsG = static_cast<uint32_t>(std::ceil(logQ / log(static_cast<double>(m_baseG))));//d=log B(Q)
        m_dgg.SetStd(0.25);//0.25 for 100 bit 0.4 for 128 bit prameters
        /*------------------------CRS-----------------------*/
        m_CRS = std::vector<NativePoly>(m_digitsG-1,NativePoly(m_dgg, m_polyParams, Format::COEFFICIENT));
        for(uint32_t i=0; i<m_digitsG-1 ;i++)
        {
            m_CRS[i].SetFormat(EVALUATION);
        }

        PreCompute(signEval);
    }

    /**
   * Performs precomputations based on the supplied parameters
   */
    void PreCompute(bool signEval = false);


    std::vector<NativePoly> GetCRS() const{
        return m_CRS;
    }

    uint32_t Getk() const {
        return m_k;
    }

    uint32_t GetN() const {
        return m_N;
    }

    const NativeInteger& GetQ() const {
        return m_Q;
    }

    const NativeInteger& Getq() const {
        return m_q;
    }

    uint32_t GetBaseG() const {
        return m_baseG;
    }

    uint32_t GetDigitsG() const {
        return m_digitsG;
    }

    uint32_t GetBaseR() const {
        return m_baseR;
    }

    uint32_t GetNumAutoKeys() const {
        return m_numAutoKeys;
    }

    const std::vector<NativeInteger>& GetDigitsR() const {
        return m_digitsR;
    }

    const std::shared_ptr<ILNativeParams> GetPolyParams() const {
        return m_polyParams;
    }

    const std::vector<NativeInteger>& GetGPower() const {
        return m_Gpower;
    }

    const std::vector<int32_t>& GetLogGen() const {
        return m_logGen;
    }

    const std::map<uint32_t, std::vector<NativeInteger>>& GetGPowerMap() const {
        return m_Gpower_map;
    }

    const DiscreteGaussianGeneratorImpl<NativeVector>& GetDgg() const {
        return m_dgg;
    }

    const std::vector<NativeInteger>& GetGateConst() const {
        return m_gateConst;
    }

    const NativePoly& GetMonomial(uint32_t i) const {
        return m_monomials[i];
    }

    BINFHE_METHOD GetMethod() const {
        return m_method;
    }

    SecretKeyDist GetKeyDist() const {
        return m_keyDist;
    }

    bool operator==(const UniEncCryptoParams& other) const {
        return m_k == other.m_k && m_N == other.m_N && m_Q == other.m_Q && m_baseR == other.m_baseR && m_baseG == other.m_baseG;
    }

    bool operator!=(const UniEncCryptoParams& other) const {
        return !(*this == other);
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("bk", m_k));
        ar(::cereal::make_nvp("bN", m_N));
        ar(::cereal::make_nvp("bQ", m_Q));
        ar(::cereal::make_nvp("bq", m_q));
        ar(::cereal::make_nvp("bR", m_baseR));
        ar(::cereal::make_nvp("bG", m_baseG));
        ar(::cereal::make_nvp("bmethod", m_method));
        ar(::cereal::make_nvp("bs", m_dgg.GetStd()));
        ar(::cereal::make_nvp("bdigitsG", m_digitsG));
        ar(::cereal::make_nvp("bparams", m_polyParams));
        ar(::cereal::make_nvp("numAutoKeys", m_numAutoKeys));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW(deserialize_error, "serialized object version " + std::to_string(version) +
                                                 " is from a later version of the library");
        }
        ar(::cereal::make_nvp("bk", m_k));
        ar(::cereal::make_nvp("bN", m_N));
        ar(::cereal::make_nvp("bQ", m_Q));
        ar(::cereal::make_nvp("bq", m_q));
        ar(::cereal::make_nvp("bR", m_baseR));
        ar(::cereal::make_nvp("bG", m_baseG));
        ar(::cereal::make_nvp("bmethod", m_method));
        double sigma = 0;
        ar(::cereal::make_nvp("bs", sigma));
        m_dgg.SetStd(sigma);
        ar(::cereal::make_nvp("bdigitsG", m_digitsG));
        ar(::cereal::make_nvp("bparams", m_polyParams));
        ar(::cereal::make_nvp("numAutoKeys", m_numAutoKeys));

        PreCompute();
    }

    std::string SerializedObjectName() const override {
        return "UniEncCryptoParams";
    }
    static uint32_t SerializedVersion() {
        return 1;
    }

    void Change_BaseG(uint32_t BaseG) {
        if (m_baseG != BaseG) {
            m_baseG  = BaseG;
            m_Gpower = m_Gpower_map[m_baseG];
            m_digitsG =
                static_cast<uint32_t>(std::ceil(log(m_Q.ConvertToDouble()) / log(static_cast<double>(m_baseG))));
        }
    }

};

}  // namespace lbcrypto

#endif  // _UniEnc_CRYPTOPARAMETERS_H_
