
#ifndef _MKLWE_PRIVATEKEY_H_
#define _MKLWE_PRIVATEKEY_H_


#include "math/math-hal.h"
#include "utils/serializable.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace lbcrypto {


class MKLWEPrivateKeyImpl;

using MKLWEPrivateKey      = std::shared_ptr<MKLWEPrivateKeyImpl>;
using ConstMKLWEPrivateKey = const std::shared_ptr<const MKLWEPrivateKeyImpl>;
/**
 * @brief Class that stores the MKLWE scheme secret key; contains a vector
 */
class MKLWEPrivateKeyImpl : public Serializable {
private:
    std::vector<NativeVector> m_s{};

public:
    MKLWEPrivateKeyImpl() = default;

    explicit MKLWEPrivateKeyImpl(const std::vector<NativeVector>& s) : m_s(s) {}

    MKLWEPrivateKeyImpl(const MKLWEPrivateKeyImpl& rhs) : m_s(rhs.m_s) {}

    MKLWEPrivateKeyImpl(MKLWEPrivateKeyImpl&& rhs) noexcept : m_s(std::move(rhs.m_s)) {}

    MKLWEPrivateKeyImpl& operator=(const MKLWEPrivateKeyImpl& rhs) {
        this->m_s = rhs.m_s;
        return *this;
    }

    MKLWEPrivateKeyImpl& operator=(MKLWEPrivateKeyImpl&& rhs) noexcept {
        this->m_s = std::move(rhs.m_s);
        return *this;
    }

    const std::vector<NativeVector>& GetElement() const {
        return m_s;
    }

    void SetElement(const std::vector<NativeVector>& s) {
        m_s = s;
    }

    uint32_t GetLength() const {
        return m_s[0].GetLength();
    }

    const NativeInteger& GetModulus() const {
        return m_s[0].GetModulus();
    }

    bool operator==(const MKLWEPrivateKeyImpl& other) const {
        return m_s == other.m_s;
    }

    bool operator!=(const MKLWEPrivateKeyImpl& other) const {
        return !(*this == other);
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("s", m_s));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW(deserialize_error, "serialized object version " + std::to_string(version) +
                                                 " is from a later version of the library");
        }

        ar(::cereal::make_nvp("s", m_s));
    }

    std::string SerializedObjectName() const override {
        return "MKLWEPrivateKey";
    }
    static uint32_t SerializedVersion() {
        return 1;
    }


};

}  // namespace lbcrypto

#endif  // _MKLWE_PRIVATEKEY_H_
