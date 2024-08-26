
#ifndef _MNTRU_KEYSWITCHKEY2_H_
#define _MNTRU_KEYSWITCHKEY2_H_

#include "math/math-hal.h"
#include "utils/serializable.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace lbcrypto {

class MNTRUSwitchingKey2Impl;
using MNTRUSwitchingKey2      = std::shared_ptr<MNTRUSwitchingKey2Impl>;
using ConstMNTRUSwitchingKey2 = const std::shared_ptr<const MNTRUSwitchingKey2Impl>;


/**
 * @brief Class that stores the MNTRU scheme switching key
 */
class MNTRUSwitchingKey2Impl : public Serializable {
private:

    std::vector<std::vector<std::vector<NativeVector>>> m_key; //
public:
    MNTRUSwitchingKey2Impl() = default;

    explicit MNTRUSwitchingKey2Impl(const std::vector<std::vector<std::vector<NativeVector>>>& key)
        : m_key(key) {}

    MNTRUSwitchingKey2Impl(const MNTRUSwitchingKey2Impl& rhs) : m_key(rhs.m_key){}

    MNTRUSwitchingKey2Impl(MNTRUSwitchingKey2Impl&& rhs) noexcept
        : m_key(std::move(rhs.m_key)) {}

    MNTRUSwitchingKey2Impl& operator=(const MNTRUSwitchingKey2Impl& rhs) {
        m_key = rhs.m_key;
        return *this;
    }

    MNTRUSwitchingKey2Impl& operator=(MNTRUSwitchingKey2Impl&& rhs) noexcept {
        m_key = std::move(rhs.m_key);
        return *this;
    }

    const std::vector<std::vector<std::vector<NativeVector>>>& GetElements() const {
        return m_key;
    }
    // const std::vector<NativeVector> GetElements_coli(uint32_t index) const {
    //     auto n = m_key[0].size();
    //     auto mod = m_key[0][0][0].GetModulus();
    //     std::vector<NativeVector> res;
    //     for(uint32_t i = 0;i<m_key.size();i++)
    //     {
    //         NativeVector col(n,mod);
    //         for(uint32_t j=0;j<n;j++)
    //         {
    //             col[j]=m_key[i][j][index];
    //         }
    //         res.push_back(col);
    //     }
    //     return res;
    // }

    void SetElements(const std::vector<std::vector<std::vector<NativeVector>>>& key) {
        m_key = key;
    }


    bool operator==(const MNTRUSwitchingKey2Impl& other) const {
        return (m_key == other.m_key);
    }

    bool operator!=(const MNTRUSwitchingKey2Impl& other) const {
        return !(*this == other);
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("ksk", m_key));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW(deserialize_error, "serialized object version " + std::to_string(version) +
                                                 " is from a later version of the library");
        }

        ar(::cereal::make_nvp("ksk", m_key));
    }

    std::string SerializedObjectName() const override {
        return "MNTRUKeySwichKey";
    }
    static uint32_t SerializedVersion() {
        return 1;
    }




};

}  // namespace lbcrypto

#endif
