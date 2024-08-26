
#ifndef _MNTRU_PRIVATEKEY_H_
#define _MNTRU_PRIVATEKEY_H_

#include "math/math-hal.h"
#include "utils/serializable.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>


namespace lbcrypto {

class MNTRUPrivateKeyImpl;

using MNTRUPrivateKey      = std::shared_ptr<MNTRUPrivateKeyImpl>;
using ConstMNTRUPrivateKey = const std::shared_ptr<const MNTRUPrivateKeyImpl>;
/**
 * @brief Class that stores the MNTRU scheme secret key; contains a matrix
 */
class MNTRUPrivateKeyImpl : public Serializable {
private:
    std::vector<std::vector<NativeVector>> m_F{};//
    std::vector<std::vector<NativeVector>> m_F_inv{};
    uint32_t m_k;

public:
    MNTRUPrivateKeyImpl() = default;

    explicit MNTRUPrivateKeyImpl(const std::vector<std::vector<NativeVector>>& F,const std::vector<std::vector<NativeVector>>& F_inv) : m_F(F),m_F_inv(F_inv),m_k(F.size()){}

    MNTRUPrivateKeyImpl(const MNTRUPrivateKeyImpl& rhs) : m_F(rhs.m_F),m_F_inv(rhs.m_F_inv),m_k(rhs.m_k) {}

    MNTRUPrivateKeyImpl(MNTRUPrivateKeyImpl&& rhs) noexcept : m_F(std::move(rhs.m_F)),m_F_inv(std::move(rhs.m_F_inv)),m_k(std::move(rhs.m_k)) {}

    MNTRUPrivateKeyImpl& operator=(const MNTRUPrivateKeyImpl& rhs) {
        this->m_F = rhs.m_F;
        this->m_F_inv = rhs.m_F_inv;
        this->m_k = rhs.m_k;
        return *this;
    }

    MNTRUPrivateKeyImpl& operator=(MNTRUPrivateKeyImpl&& rhs) noexcept {
        this->m_F = std::move(rhs.m_F);
        this->m_F_inv = std::move(rhs.m_F_inv);
        this->m_k = std::move(rhs.m_k);
        return *this;
    }

    const std::vector<std::vector<NativeVector>>& GetF() const {
        return m_F;
    }

    const std::vector<NativeVector> GetF_col0() const {
        auto n = m_F[0][0].GetLength();
        auto mod = m_F[0][0].GetModulus();
        std::vector<NativeVector> res;
        for(uint32_t i = 0;i<m_k;i++)
        {
            NativeVector col(n,mod);
            for(uint32_t j=0;j<n;j++)
            {
                col[j]=m_F[i][j][0];
            }
            res.push_back(col);
        }
        return res;
    }

    const std::vector<NativeVector> GetF_inv_col0() const {
        auto n = m_F_inv[0][0].GetLength();
        auto mod = m_F_inv[0][0].GetModulus();
        std::vector<NativeVector> res;
        for(uint32_t i = 0;i<m_k;i++)
        {
            NativeVector col(n,mod);
            for(uint32_t j=0;j<n;j++)
            {
                col[j]=m_F_inv[i][j][0];
            }
            res.push_back(col);
        }
        return res;
    }
    const std::vector<NativeVector> GetF_inv_coli(uint32_t index) const {
        auto n = m_F_inv[0][0].GetLength();
        auto mod = m_F_inv[0][0].GetModulus();
        std::vector<NativeVector> res;
        for(uint32_t i = 0;i<m_k;i++)
        {
            NativeVector col(n,mod);
            for(uint32_t j=0;j<n;j++)
            {
                col[j]=m_F_inv[i][j][index];
            }
            res.push_back(col);
        }
        return res;
    }


    const std::vector<std::vector<NativeVector>>& GetF_inv() const {
        return m_F_inv;
    }
    const uint32_t& Getk() const {
        return m_k;
    }


    void SetF(const std::vector<std::vector<NativeVector>>& F) {
        m_F = F;
    }

    void SetF_inv(const std::vector<std::vector<NativeVector>>& F_inv) {
        m_F_inv = F_inv;
    }

    uint32_t GetLength() const {
        return m_F[0][0].GetLength();
    }

    const NativeInteger& GetModulus() const {
        return m_F[0][0].GetModulus();
    }

    bool operator==(const MNTRUPrivateKeyImpl& other) const {
        return m_F == other.m_F && m_F_inv == other.m_F_inv;
    }

    bool operator!=(const MNTRUPrivateKeyImpl& other) const {
        return !(*this == other);
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("F", m_F));
        ar(::cereal::make_nvp("F_inv", m_F_inv));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW(deserialize_error, "serialized object version " + std::to_string(version) +
                                                 " is from a later version of the library");
        }

        ar(::cereal::make_nvp("F", m_F));
        ar(::cereal::make_nvp("F_inv", m_F_inv));
    }

    std::string SerializedObjectName() const override {
        return "MNTRUPrivateKey";
    }
    static uint32_t SerializedVersion() {
        return 1;
    }

};

}  // namespace lbcrypto

#endif  // _MNTRU_PRIVATEKEY_H_