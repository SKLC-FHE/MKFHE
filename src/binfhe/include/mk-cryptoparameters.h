
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

    DiscreteGaussianGeneratorImpl<NativeVector> m_dggR;
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
         m_dggR.SetStd(0.15);//0.15 for 100 bit 0.16 for 128 bit prameters
         // Evaluating the security strength of this parameter using the LWE estimator
//    params = LWE.Parameters(n=2048, q=2**27, Xs=ND.DiscreteGaussian(0.15), Xe=ND.DiscreteGaussian(0.25)) 
//    LWEParameters(n=2048, q=134217728, Xs=D(σ=0.15), Xe=D(σ=0.40), m=+Infinity, tag=None)
// usvp                 :: rop: ≈2^213.5, red: ≈2^213.5, δ: 1.002823, β: 648, d: 3552, tag: usvp
// bdd                  :: rop: ≈2^211.6, red: ≈2^211.3, svp: ≈2^209.3, β: 640, η: 674, d: 3555, tag: bdd
// But using the estimator, only two types of attacks appear, usvp and bdd, without dual and hybrid attacks. This seems to be due to the estimator, as when the secret key distribution is too small, it is only suitable for using a sparse ternary distribution.
// So we choose a set of sparse ternary distributions to simulate our discrete Gaussian distribution with sigma=0.15
// params = LWE.Parameters(n=2048, q=2**27, Xs= ND.SparseTernary(2048, 22), Xe=ND.DiscreteGaussian(0.25))
// also: LWEParameters(n=2048, q=134217728, Xs=D(σ=0.15), Xe=D(σ=0.40), m=+Infinity, tag=None)
// usvp                 :: rop: ≈2^213.2, red: ≈2^213.2, δ: 1.002826, β: 647, d: 3543, tag: usvp
// bdd                  :: rop: ≈2^211.3, red: ≈2^211.0, svp: ≈2^209.0, β: 639, η: 673, d: 3545, tag: bdd
// bdd_hybrid           :: rop: ≈2^133.0, red: ≈2^132.7, svp: ≈2^130.6, β: 308, η: 26, ζ: 1023, |S|: ≈2^88.1, d: 1820, prob: ≈2^-12.5, ↻: ≈2^14.7, tag: hybrid
// bdd_mitm_hybrid      :: rop: ≈2^115.4, red: ≈2^114.5, svp: ≈2^114.4, β: 209, η: 2, ζ: 1426, |S|: ≈2^139.3, d: 1083, prob: ≈2^-22.4, ↻: ≈2^24.6, tag: hybrid
// dual                 :: rop: ≈2^218.0, mem: ≈2^135.0, m: 1611, β: 660, d: 3659, ↻: 1, tag: dual
// dual_hybrid          :: rop: ≈2^122.2, mem: ≈2^82.4, m: 702, β: 182, d: 1426, ↻: ≈2^37.6, ζ: 1324, h1: 7, tag: dual_hybrid
// dual_mitm_hybrid     :: rop: ≈2^116.6, mem: ≈2^83.6, m: 712, k: 853, ↻: ≈2^32.6, β: 196, d: 1203, ζ: 1557, h1: 16, tag: dual_mitm_hybrid
// The security level is sufficient for 100-bit security.
// For 128-bit parameters
// params = LWE.Parameters(n=2048, q=2**27, Xs= ND.SparseTernary(2048, 30), Xe=ND.DiscreteGaussian(0.4))
// LWEParameters(n=2048, q=134217728, Xs=D(σ=0.17), Xe=D(σ=0.40), m=+Infinity, tag=None)
// usvp                 :: rop: ≈2^219.9, red: ≈2^219.9, δ: 1.002752, β: 671, d: 3602, tag: usvp
// bdd                  :: rop: ≈2^218.0, red: ≈2^217.7, svp: ≈2^215.7, β: 663, η: 697, d: 3585, tag: bdd
// bdd_hybrid           :: rop: ≈2^149.2, red: ≈2^148.3, svp: ≈2^148.1, β: 336, η: 2, ζ: 1024, |S|: ≈2^103.1, d: 1903, prob: ≈2^-20.3, ↻: ≈2^22.5, tag: hybrid
// bdd_mitm_hybrid      :: rop: ≈2^134.1, red: ≈2^133.3, svp: ≈2^133.0, β: 260, η: 2, ζ: 1334, |S|: ≈2^166.4, d: 1355, prob: ≈2^-26.8, ↻: ≈2^29.0, tag: hybrid
// dual                 :: rop: ≈2^225.2, mem: ≈2^138.0, m: 1631, β: 686, d: 3679, ↻: 1, tag: dual
// dual_hybrid          :: rop: ≈2^142.5, mem: ≈2^101.7, m: 843, β: 253, d: 1730, ↻: ≈2^38.3, ζ: 1161, h1: 9, tag: dual_hybrid
// dual_mitm_hybrid     :: rop: ≈2^140.0, mem: ≈2^103.6, m: 850, k: 809, ↻: ≈2^36.0, β: 269, d: 1429, ζ: 1469, h1: 21, tag: dual_mitm_hybrid

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
     const DiscreteGaussianGeneratorImpl<NativeVector>& GetDggR() const {
        return m_dggR;
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
