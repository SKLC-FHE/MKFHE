
#ifndef _MNTRU_CIPHERTEXT_H_
#define _MNTRU_CIPHERTEXT_H_


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
/**
 * @brief Class that stores a MNTRU scheme ciphertext; composed of a vector of NativeVector m_elements
 */
class MNTRUCiphertextImpl;
using MNTRUCiphertext      = std::shared_ptr<MNTRUCiphertextImpl>;
using ConstMNTRUCiphertext = const std::shared_ptr<const MNTRUCiphertextImpl>;


class MNTRUCiphertextImpl : public Serializable {
private:
    std::vector<NativeVector> m_elements{};  
    NativeInteger m_p = 4;  // pt modulus
    
public:
    MNTRUCiphertextImpl() = default;

    MNTRUCiphertextImpl(const std::vector<NativeVector>& elements) : m_elements(elements) {}


    MNTRUCiphertextImpl(const MNTRUCiphertextImpl& rhs) :  m_elements(rhs.m_elements) {}

    MNTRUCiphertextImpl(MNTRUCiphertextImpl&& rhs) noexcept : m_elements(std::move(rhs.m_elements)) {}

    MNTRUCiphertextImpl& operator=(const MNTRUCiphertextImpl& rhs) {
        this->m_elements = rhs.m_elements;
        return *this;
    }

    MNTRUCiphertextImpl& operator=(MNTRUCiphertextImpl&& rhs) noexcept {
        this->m_elements = std::move(rhs.m_elements);
        return *this;
    }

    const std::vector<NativeVector>& GetElements() const {
        return m_elements;
    }

    std::vector<NativeVector>& GetElements() {
        return m_elements;
    }

    const NativeVector& GetElements(std::size_t i) const {
        return m_elements[i];
    }

    NativeVector& GetElements(std::size_t i) {
        return m_elements[i];
    }

    const NativeInteger& GetModulus() const {
        return m_elements[0].GetModulus();
    }


    uint32_t GetLength() const {
        return m_elements[0].GetLength();
    }

    const NativeInteger& GetptModulus() const {
        return m_p;
    }

    uint32_t Getk() const {
        return m_elements.size();
    }


    void SetElements(const std::vector<NativeVector>& elements) {
        m_elements.resize(elements.size());
        for(uint32_t i=0;i<m_elements.size();i++)
        {
            m_elements[i]=elements[i];
        }
    }
    void SetModulus(const NativeInteger& mod) {
        for(uint32_t i=0;i<m_elements.size();i++)
        {
            m_elements[i].ModEq(mod);
            m_elements[i].SetModulus(mod);
        }
    }
    
    void SetptModulus(const NativeInteger& pmod) {
        m_p = pmod;
    }



    bool operator==(const MNTRUCiphertextImpl& other) const {
        return m_elements == other.m_elements;
    }

    bool operator!=(const MNTRUCiphertextImpl& other) const {
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
        return "MNTRUCiphertext";
    }
    static uint32_t SerializedVersion() {
        return 1;
    }


};

}  // namespace lbcrypto

#endif  // _MNTRU_CIPHERTEXT_H_
