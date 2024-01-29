
#ifndef _MKLWE_CRYPTOPARAMETERS_H_
#define _MKLWE_CRYPTOPARAMETERS_H_

#include "binfhe-constants.h"

#include "math/discretegaussiangenerator.h"
#include "math/math-hal.h"
#include "utils/serializable.h"

#include <string>
#include <utility>
#include <vector>

namespace lbcrypto {

/**
 * @brief Class that stores all parameters for the MKLWE scheme
 */
class MKLWECryptoParams : public Serializable {
private:
    uint32_t m_k;
    // modulus for the additive MKLWE scheme
    NativeInteger m_q{};
    // modulus for the RingGSW/RingMKLWE scheme
    NativeInteger m_Q{};
    // modulus for key-switching
    NativeInteger m_qKS{};
    // lattice parameter for the additive MKLWE scheme
    uint32_t m_n{};
    // ring dimension for RingGSW/RingMKLWE scheme
    uint32_t m_N{};
    // Base used in key switching
    uint32_t m_baseKS{};
    // Secret key distribution: GAUSSIAN, UNIFORM_TERNARY, etc.
    SecretKeyDist m_keyDist{SecretKeyDist::UNIFORM_TERNARY};
    // Error distribution generator
    DiscreteGaussianGeneratorImpl<NativeVector> m_dgg;
    // Error distribution generator for key switching
    DiscreteGaussianGeneratorImpl<NativeVector> m_ks_dgg;

public:
    // NativeInteger m_qKS = 1<<20; //PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(26, 2048), 2048);
    MKLWECryptoParams() = default;

    /**
   * Main constructor for MKLWECryptoParams
   *
   * @param n lattice parameter for additive MKLWE scheme
   * @param N ring dimension for RingGSW/RMKLWE used in bootstrapping
   * @param q modulus for additive MKLWE
   * @param Q modulus for RingGSW/RMKLWE used in bootstrapping
   * @param q_KS modulus for key switching
   * @param std standard deviation
   * @param baseKS the base used for key switching
   * @param keyDist the key distribution
   */
    //explicit 可以有效地防止隐式转换带来的意外结果，提高代码的可读性和安全性。
    explicit MKLWECryptoParams(uint32_t k,uint32_t n, uint32_t N, const NativeInteger& q, const NativeInteger& Q,
                             const NativeInteger& q_KS, double std, uint32_t baseKS,
                             SecretKeyDist keyDist = UNIFORM_TERNARY)
        : m_k(k), m_q(q), m_Q(Q), m_qKS(q_KS), m_n(n), m_N(N), m_baseKS(baseKS), m_keyDist(keyDist) //成员变量初始化
    {
        if(!m_k)
            OPENFHE_THROW(config_error, "m_k (number of users) can not be zero");
        if(!m_n)
            OPENFHE_THROW(config_error, "m_n (lattice parameter) can not be zero");
        if(!m_N)
            OPENFHE_THROW(config_error, "m_N (ring dimension) can not be zero");
        if(!m_q)
            OPENFHE_THROW(config_error, "m_q (modulus for additive MKLWE) can not be zero");
        if(!m_Q)
            OPENFHE_THROW(config_error, "m_Q (modulus for RingGSW/RMKLWE) can not be zero");
        if(!q_KS)
            OPENFHE_THROW(config_error, "q_KS (modulus for key switching) can not be zero");
        if(!m_baseKS)
            OPENFHE_THROW(config_error, "m_baseKS (the base used for key switching) can not be zero");
        
        if (m_Q.GetMSB() > MAX_MODULUS_SIZE)
            OPENFHE_THROW(config_error, "Q.GetMSB() > MAX_MODULUS_SIZE");
        m_dgg.SetStd(std);
        m_ks_dgg.SetStd(std);
    }

    // TODO: add m_qKS, m_ks_dgg, and m_keyDist to copy/move operations?
    MKLWECryptoParams(const MKLWECryptoParams& rhs)
        : m_k(rhs.m_k),
          m_q(rhs.m_q),
          m_Q(rhs.m_Q),
          // m_qKS(rhs.m_qKS),
          m_n(rhs.m_n),
          m_N(rhs.m_N),
          m_baseKS(rhs.m_baseKS) 
    {
        this->m_dgg.SetStd(rhs.m_dgg.GetStd());
        // this->m_ks_dgg.SetStd(rhs.m_ks_dgg.GetStd());
    }
    MKLWECryptoParams(MKLWECryptoParams&& rhs) noexcept
        : m_k(std::move(rhs.m_k)),
          m_q(std::move(rhs.m_q)),
          m_Q(std::move(rhs.m_Q)),
          // m_qKS(std::move(rhs.m_qKS)),
          m_n(rhs.m_n),
          m_N(rhs.m_N),
          m_baseKS(rhs.m_baseKS) 
    {
        this->m_dgg.SetStd(rhs.m_dgg.GetStd());
        // this->m_ks_dgg.SetStd(rhs.m_ks_dgg.GetStd());
    }

    MKLWECryptoParams& operator=(const MKLWECryptoParams& rhs) {
        this->m_k = rhs.m_k;
        this->m_q = rhs.m_q;
        this->m_Q = rhs.m_Q;
        // this->m_qKS    = rhs.m_qKS;
        this->m_n      = rhs.m_n;
        this->m_N      = rhs.m_N;
        this->m_baseKS = rhs.m_baseKS;
        this->m_dgg.SetStd(rhs.m_dgg.GetStd());
        // this->m_ks_dgg.SetStd(rhs.m_ks_dgg.GetStd());
        return *this;
    }

    MKLWECryptoParams& operator=(MKLWECryptoParams&& rhs) noexcept {
        this->m_k = std::move(rhs.m_k);
        this->m_q = std::move(rhs.m_q);
        this->m_Q = std::move(rhs.m_Q);
        // this->m_qKS    = std::move(rhs.m_qKS);
        this->m_n      = rhs.m_n;
        this->m_N      = rhs.m_N;
        this->m_baseKS = rhs.m_baseKS;
        this->m_dgg.SetStd(rhs.m_dgg.GetStd());
        // this->m_ks_dgg.SetStd(rhs.m_ks_dgg.GetStd());
        return *this;
    }

    uint32_t Getk() const {
        return m_k;
    }

    uint32_t Getn() const {
        return m_n;
    }

    uint32_t GetN() const {
        return m_N;
    }

    const NativeInteger& Getq() const {
        return m_q;
    }

    const NativeInteger& GetQ() const {
        return m_Q;
    }

    const NativeInteger& GetqKS() const {
        return m_qKS;
    }

    uint32_t GetBaseKS() const {
        return m_baseKS;
    }

    const DiscreteGaussianGeneratorImpl<NativeVector>& GetDgg() const {
        return m_dgg;
    }

    const DiscreteGaussianGeneratorImpl<NativeVector>& GetDggKS() const {
        return m_ks_dgg;
    }

    SecretKeyDist GetKeyDist() const {
        return m_keyDist;
    }

    bool operator==(const MKLWECryptoParams& other) const {
        return m_k == other.m_k && m_n == other.m_n && m_N == other.m_N && m_q == other.m_q && m_Q == other.m_Q &&
               m_dgg.GetStd() == other.m_dgg.GetStd() && m_baseKS == other.m_baseKS;
    }

    bool operator!=(const MKLWECryptoParams& other) const {
        return !(*this == other);
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("k", m_k));
        ar(::cereal::make_nvp("n", m_n));
        ar(::cereal::make_nvp("N", m_N));
        ar(::cereal::make_nvp("q", m_q));
        ar(::cereal::make_nvp("Q", m_Q));
        ar(::cereal::make_nvp("qKS", m_qKS));
        ar(::cereal::make_nvp("sigma", m_dgg.GetStd()));
        ar(::cereal::make_nvp("sigmaKS", m_ks_dgg.GetStd()));
        ar(::cereal::make_nvp("bKS", m_baseKS));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW(deserialize_error, "serialized object version " + std::to_string(version) +
                                                 " is from a later version of the library");
        }
        ar(::cereal::make_nvp("k", m_k));
        ar(::cereal::make_nvp("n", m_n));
        ar(::cereal::make_nvp("N", m_N));
        ar(::cereal::make_nvp("q", m_q));
        ar(::cereal::make_nvp("Q", m_Q));
        ar(::cereal::make_nvp("qKS", m_qKS));
        double sigma = 0;
        ar(::cereal::make_nvp("sigma", sigma));
        double sigmaKS = 0;
        ar(::cereal::make_nvp("sigmaKS", sigmaKS));
        m_dgg.SetStd(sigma);
        m_ks_dgg.SetStd(sigmaKS);
        ar(::cereal::make_nvp("bKS", m_baseKS));
    }

    std::string SerializedObjectName() const override {
        return "MKLWECryptoParams";
    }
    static uint32_t SerializedVersion() {
        return 1;
    }


};

}  // namespace lbcrypto

#endif  // _MKLWE_CRYPTOPARAMETERS_H_
