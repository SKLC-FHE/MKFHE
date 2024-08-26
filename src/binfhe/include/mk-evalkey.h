
#ifndef _MK_EVAL_KEY_H_
#define _MK_EVAL_KEY_H_

#include "mntru-ciphertext.h"
#include "mntru-keyswitchkey.h"
#include "mntru-keyswitchkey2.h"
#include "mntru-privatekey.h"
#include "mntru-cryptoparameters.h"

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

class UniEncEvalKeyImpl;
using UniEncEvalKey      = std::shared_ptr<UniEncEvalKeyImpl>;
using ConstUniEncEvalKey = const std::shared_ptr<const UniEncEvalKeyImpl>;

/**
 * @brief Class that stores a UniEnc ciphertext; a two-dimensional vector of
 * ring elements
 */
class UniEncEvalKeyImpl : public Serializable {
private:
    std::vector<std::vector<NativePoly>> m_elements;//  
public:
    UniEncEvalKeyImpl() = default;

    UniEncEvalKeyImpl(uint32_t rowSize, uint32_t colSize) noexcept
        : m_elements(rowSize, std::vector<NativePoly>(colSize)) {}

    explicit UniEncEvalKeyImpl(const std::vector<std::vector<NativePoly>>& elements) : m_elements(elements) {}

    UniEncEvalKeyImpl(const UniEncEvalKeyImpl& rhs) : m_elements(rhs.m_elements) {}

    UniEncEvalKeyImpl(UniEncEvalKeyImpl&& rhs) noexcept : m_elements(std::move(rhs.m_elements)) {}

    UniEncEvalKeyImpl& operator=(const UniEncEvalKeyImpl& rhs) {
        UniEncEvalKeyImpl::m_elements = rhs.m_elements;
        return *this;
    }

    UniEncEvalKeyImpl& operator=(UniEncEvalKeyImpl&& rhs) noexcept {
        UniEncEvalKeyImpl::m_elements = std::move(rhs.m_elements);
        return *this;
    }

    const std::vector<std::vector<NativePoly>>& GetElements() const {
        return m_elements;
    }

    void SetElements(const std::vector<std::vector<NativePoly>>& elements) {
        m_elements = elements;
    }

    /**
   * Switches between COEFFICIENT and Format::EVALUATION polynomial
   * representations using NTT
   */
    void SetFormat(const Format format) {
        for (size_t i = 0; i < m_elements.size(); ++i) {
            auto& l1 = m_elements[i];
            for (size_t j = 0; j < l1.size(); ++j)
                l1[j].SetFormat(format);
        }
    }

    std::vector<NativePoly>& operator[](uint32_t i) {
        return m_elements[i];
    }

    const std::vector<NativePoly>& operator[](uint32_t i) const {
        return m_elements[i];
    }

    bool operator==(const UniEncEvalKeyImpl& other) const {
        if (m_elements.size() != other.m_elements.size())
            return false;
        for (size_t i = 0; i < m_elements.size(); ++i) {
            const auto& l1 = m_elements[i];
            const auto& o1 = other.m_elements[i];
            if (l1.size() != o1.size())
                return false;
            for (size_t j = 0; j < l1.size(); ++j) {
                if (l1[j] != o1[j])
                    return false;
            }
        }
        return true;
    }

    bool operator!=(const UniEncEvalKeyImpl& other) const {
        return !(*this == other);
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("elements", m_elements));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW(deserialize_error, "serialized object version " + std::to_string(version) +
                                                 " is from a later version of the library");
        }
        ar(::cereal::make_nvp("elements", m_elements));
    }

    std::string SerializedObjectName() const override {
        return "UniEncEvalKey";
    }
    static uint32_t SerializedVersion() {
        return 1;
    }


};

}  // namespace lbcrypto

#endif  // _UniEnc_EVAL_KEY_H_
