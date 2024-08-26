#ifndef _MK_BTKEY_H_
#define _MK_BTKEY_H_


//
#include "mntru-ciphertext.h"
#include "mntru-keyswitchkey.h"
#include "mntru-keyswitchkey2.h"
#include "mntru-privatekey.h"
#include "mntru-cryptoparameters.h"

//
#include "mklwe-ciphertext.h"
#include "mklwe-keyswitchkey.h"
#include "mklwe-privatekey.h"
#include "mklwe-cryptoparameters.h"


//
#include "mk-evalkey.h"

#include "lattice/lat-hal.h"
#include "math/discretegaussiangenerator.h"
#include "math/nbtheory.h"
#include "utils/serializable.h"
#include "utils/utilities.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>
#include <map>

namespace lbcrypto {

class UniEncACCKeyImpl;
using UniEncACCKey      = std::shared_ptr<UniEncACCKeyImpl>;
using ConstUniEncACCKey = const std::shared_ptr<const UniEncACCKeyImpl>;

/**
 * @brief Class that stores the refresh key (used in bootstrapping)
 * A three-dimensional vector of UniEnc ciphertexts
 */
class UniEncACCKeyImpl : public Serializable {

private:
    using dim3_t = std::vector<UniEncEvalKey>;
    using dim2_t = std::vector<dim3_t>;
    using dim1_t = std::vector<dim2_t>;

    std::vector<std::vector<std::vector<UniEncEvalKey>>> m_key; // k 


public:
/*-------------类初始化--------------*/
    UniEncACCKeyImpl() = default;

    UniEncACCKeyImpl(uint32_t dim1, uint32_t dim2, uint32_t dim3) : m_key(dim1, dim2_t(dim2, dim3_t(dim3))) {}

    explicit UniEncACCKeyImpl(const std::vector<std::vector<std::vector<UniEncEvalKey>>>& key) : m_key(key) {}

    UniEncACCKeyImpl(const UniEncACCKeyImpl& rhs) : m_key(rhs.m_key) {}

    UniEncACCKeyImpl(UniEncACCKeyImpl&& rhs) noexcept : m_key(std::move(rhs.m_key)) {}

    UniEncACCKeyImpl& operator=(const UniEncACCKeyImpl& rhs) {
        this->m_key = rhs.m_key;
        return *this;
    }

    UniEncACCKeyImpl& operator=(UniEncACCKeyImpl&& rhs) noexcept {
        this->m_key = std::move(rhs.m_key);
        return *this;
    }

    const std::vector<std::vector<std::vector<UniEncEvalKey>>>& GetElements() const {
        return m_key;
    }

    void SetElements(const std::vector<std::vector<std::vector<UniEncEvalKey>>>& key) {
        m_key = key;
    }

    std::vector<std::vector<UniEncEvalKey>>& operator[](uint32_t i) {
        return m_key[i];
    }

    const std::vector<std::vector<UniEncEvalKey>>& operator[](uint32_t i) const {
        return m_key[i];
    }

    bool operator==(const UniEncACCKeyImpl& other) const {
        // as UniEncEvalKey is shared_ptr<UniEncEvalKeyImpl>, we have to loop through all elements to compare them
        if (m_key.size() != other.m_key.size())
            return false;
        for (size_t i = 0; i < m_key.size(); ++i) {
            const auto& l1 = m_key[i];
            const auto& o1 = other.m_key[i];
            if (l1.size() != o1.size())
                return false;
            for (size_t j = 0; j < l1.size(); ++j) {
                const auto& l2 = l1[j];
                const auto& o2 = o1[j];
                if (l2.size() != o2.size())
                    return false;
                for (size_t k = 0; k < l2.size(); ++k) {
                    const auto& l3 = l2[k];
                    const auto& o3 = o2[k];
                    if (l3.get() == nullptr || o3.get() == nullptr) {
                        if (l3.get() != o3.get())
                            return false;
                    }
                    else {
                        if (*l3 != *o3)
                            return false;
                    }
                }
            }
        }
        return true;
    }

    bool operator!=(const UniEncACCKeyImpl& other) const {
        return !(*this == other);
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("k", m_key));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW(deserialize_error, "serialized object version " + std::to_string(version) +
                                                 " is from a later version of the library");
        }
        ar(::cereal::make_nvp("k", m_key));
    }

    std::string SerializedObjectName() const override {
        return "UniEncACCKey";
    }
    static uint32_t SerializedVersion() {
        return 1;
    }


};


}  // namespace lbcrypto

#endif