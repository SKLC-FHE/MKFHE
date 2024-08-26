
#ifndef _BINFHE_BASE_PARAMS_H_
#define _BINFHE_BASE_PARAMS_H_

#include "lattice/lat-hal.h"
#include "math/discretegaussiangenerator.h"
#include "math/nbtheory.h"
#include "utils/serializable.h"
#include "utils/utilities.h"

#include "binfhe-constants.h"

#include "lwe-ciphertext.h"
#include "lwe-keyswitchkey.h"
#include "lwe-cryptoparameters.h"
#include "rgsw-cryptoparameters.h"
#include "vntru-cryptoparameters.h"
#include "mk-cryptoparameters.h"

#include "mntru-ciphertext.h"
#include "mntru-keyswitchkey.h"
#include "mntru-keyswitchkey2.h"

#include "mntru-cryptoparameters.h"

#include "mklwe-ciphertext.h"
#include "mklwe-keyswitchkey.h"
#include "mklwe-cryptoparameters.h"



#include <memory>
#include <string>
#include <utility>
#include <vector>
#include <map>

namespace lbcrypto {

/**
 * @brief Class that stores all parameters for the RingGSW scheme used in
 * bootstrapping
 */
class BinFHECryptoParams : public Serializable {
private:
    // shared pointer to an instance of LWECryptoParams
    std::shared_ptr<LWECryptoParams> m_LWEParams{nullptr};

    // shared pointer to an instance of RGSWCryptoParams
    std::shared_ptr<RingGSWCryptoParams> m_RGSWParams{nullptr};

 
    // shared pointer to an instance of VNTRUCryptoParams
    std::shared_ptr<VectorNTRUCryptoParams> m_VNTRUParams{nullptr};

    //mkfhe
    // shared pointer to an instance of MNTRUCryptoParams
    std::shared_ptr<MNTRUCryptoParams> m_MNTRUParams{nullptr};

    std::shared_ptr<MKLWECryptoParams> m_MKLWEParams{nullptr};


    // shared pointer to an instance of MNTRUCryptoParams
    std::shared_ptr<UniEncCryptoParams> m_UniEncParams{nullptr};


public:
    BinFHECryptoParams() = default;

    /**
   * Main constructor for BinFHECryptoParams
   *
   * @param lweparams a shared poiter to an instance of LWECryptoParams
   * @param rgswparams a shared poiter to an instance of RingGSWCryptoParams
   */

    BinFHECryptoParams(const std::shared_ptr<LWECryptoParams>& lweparams,
                       const std::shared_ptr<RingGSWCryptoParams>& rgswparams)
        : m_LWEParams(lweparams), m_RGSWParams(rgswparams) {}


 
    BinFHECryptoParams(const std::shared_ptr<LWECryptoParams>& lweparams,
                    const std::shared_ptr<VectorNTRUCryptoParams>& vntruparams)
        : m_LWEParams(lweparams), m_VNTRUParams(vntruparams) {}


    //mkfhe
    BinFHECryptoParams(const std::shared_ptr<MNTRUCryptoParams>& mntruparams,
                    const std::shared_ptr<UniEncCryptoParams>& uniencparams)
        : m_MNTRUParams(mntruparams), m_UniEncParams(uniencparams) {}

    BinFHECryptoParams(const std::shared_ptr<MKLWECryptoParams>& mklweparams,
                    const std::shared_ptr<UniEncCryptoParams>& uniencparams)
        : m_MKLWEParams(mklweparams), m_UniEncParams(uniencparams) {}
    
    /**
   * Getter for LWE params
   * @return
   */
    const std::shared_ptr<LWECryptoParams>& GetLWEParams() const {
        return m_LWEParams;
    }
   

    const std::shared_ptr<MKLWECryptoParams>& GetMKLWEParams() const {
        return m_MKLWEParams;
    }


    /**
   * Getter for RingGSW params
   * @return
   */
    const std::shared_ptr<RingGSWCryptoParams>& GetRingGSWParams() const {
        return m_RGSWParams;
    }

    /**

   * Getter for VectorNTRU params
   * @return
   */
    const std::shared_ptr<VectorNTRUCryptoParams>& GetVectorNTRUParams() const {
        return m_VNTRUParams;
    }

    /**
   * Getter for MatrixNTRU params
   * @return
   */
    const std::shared_ptr<MNTRUCryptoParams>& GetMatrixNTRUParams() const {
        return m_MNTRUParams;
    }

    /**
   * Getter for MatrixNTRU params
   * @return
   */
    const std::shared_ptr<UniEncCryptoParams>& GetUniEncParams() const {
        return m_UniEncParams;
    }

    /**
   * Compare two BinFHE sets of parameters
   * @return
   */
    bool operator==(const BinFHECryptoParams& other) const {
        return *m_LWEParams == *other.m_LWEParams && *m_RGSWParams == *other.m_RGSWParams && *m_VNTRUParams == *other.m_VNTRUParams && *m_MNTRUParams == *other.m_MNTRUParams && *m_UniEncParams == *other.m_UniEncParams;
    }

    bool operator!=(const BinFHECryptoParams& other) const {
        return !(*this == other);
    }

    /**
     * @brief 
     * @tparam Archive 
     * @param ar 
     * @param version 
     */
    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
       
        ar(::cereal::make_nvp("lweparams", m_LWEParams));
        ar(::cereal::make_nvp("rgswparams", m_RGSWParams));
      
        ar(::cereal::make_nvp("vntruparams", m_VNTRUParams));
        ar(::cereal::make_nvp("mntruparams", m_MNTRUParams));
        ar(::cereal::make_nvp("uniencparams", m_UniEncParams));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW(deserialize_error, "serialized object version " + std::to_string(version) +
                                                 " is from a later version of the library");
        }
        ar(::cereal::make_nvp("lweparams", m_LWEParams));
        ar(::cereal::make_nvp("rgswparams", m_RGSWParams));
    
        ar(::cereal::make_nvp("vntruparams", m_VNTRUParams));
        ar(::cereal::make_nvp("mntruparams", m_MNTRUParams));
        ar(::cereal::make_nvp("uniencparams", m_UniEncParams));
    }

    std::string SerializedObjectName() const override {
        return "BinFHECryptoParams";
    }

    static uint32_t SerializedVersion() {
        return 1;
    }


};

}  // namespace lbcrypto

#endif  // _BINFHE_BASE_PARAMS_H_
