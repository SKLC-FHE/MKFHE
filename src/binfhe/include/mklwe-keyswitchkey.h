

#ifndef _MKLWE_KEYSWITCHKEY_H_
#define _MKLWE_KEYSWITCHKEY_H_

#include "lwe-keyswitchkey-fwd.h"

#include "math/math-hal.h"
#include "utils/serializable.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace lbcrypto {

class MKLWESwitchingKeyImpl;

using MKLWESwitchingKey      = std::shared_ptr<MKLWESwitchingKeyImpl>;
using ConstMKLWESwitchingKey = const std::shared_ptr<const MKLWESwitchingKeyImpl>;

/**
 * @brief Class that stores the MKLWE scheme switching key
 */
class MKLWESwitchingKeyImpl : public Serializable {
private:
    std::vector<std::vector<std::vector<std::vector<NativeVector>>>> m_keyA;  
    std::vector<std::vector<std::vector<std::vector<NativeInteger>>>> m_keyB;
public:
    MKLWESwitchingKeyImpl() = default;

    explicit MKLWESwitchingKeyImpl(const std::vector<std::vector<std::vector<std::vector<NativeVector>>>> & keyA,
                                 const std::vector<std::vector<std::vector<std::vector<NativeInteger>>>> & keyB)
        : m_keyA(keyA), m_keyB(keyB) {}

    MKLWESwitchingKeyImpl(const MKLWESwitchingKeyImpl& rhs) : m_keyA(rhs.m_keyA), m_keyB(rhs.m_keyB) {}

    MKLWESwitchingKeyImpl(MKLWESwitchingKeyImpl&& rhs) noexcept
        : m_keyA(std::move(rhs.m_keyA)), m_keyB(std::move(rhs.m_keyB)) {}

    MKLWESwitchingKeyImpl& operator=(const MKLWESwitchingKeyImpl& rhs) {
        m_keyA = rhs.m_keyA;
        m_keyB = rhs.m_keyB;
        return *this;
    }

    MKLWESwitchingKeyImpl& operator=(MKLWESwitchingKeyImpl&& rhs) noexcept {
        m_keyA = std::move(rhs.m_keyA);
        m_keyB = std::move(rhs.m_keyB);
        return *this;
    }

    const std::vector<std::vector<std::vector<std::vector<NativeVector>>>>& GetElementsA() const {
        return m_keyA;
    }

    const std::vector<std::vector<std::vector<std::vector<NativeInteger>>>>& GetElementsB() const {
        return m_keyB;
    }

    void SetElementsA(const std::vector<std::vector<std::vector<std::vector<NativeVector>>>>& keyA) {
        m_keyA = keyA;
    }

    void SetElementsB(const std::vector<std::vector<std::vector<std::vector<NativeInteger>>>>& keyB) {
        m_keyB = keyB;
    }

    bool operator==(const MKLWESwitchingKeyImpl& other) const {
        return (m_keyA == other.m_keyA && m_keyB == other.m_keyB);
    }

    bool operator!=(const MKLWESwitchingKeyImpl& other) const {
        return !(*this == other);
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("a", m_keyA));
        ar(::cereal::make_nvp("b", m_keyB));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW(deserialize_error, "serialized object version " + std::to_string(version) +
                                                 " is from a later version of the library");
        }

        ar(::cereal::make_nvp("a", m_keyA));
        ar(::cereal::make_nvp("b", m_keyB));
    }

    std::string SerializedObjectName() const override {
        return "MKLWEPrivateKey";
    }
    static uint32_t SerializedVersion() {
        return 1;
    }


};

}  // namespace lbcrypto

#endif
