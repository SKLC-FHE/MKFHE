//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================

#ifndef _MKLWE_CIPHERTEXT_H_
#define _MKLWE_CIPHERTEXT_H_

#include "math/math-hal.h"
#include "utils/serializable.h"

#include <string>
#include <utility>
#include <vector>

namespace lbcrypto {

    
class MKLWECiphertextImpl;

using MKLWECiphertext      = std::shared_ptr<MKLWECiphertextImpl>;
using ConstMKLWECiphertext = const std::shared_ptr<const MKLWECiphertextImpl>;
/**
 * @brief Class that stores a MKLWE scheme ciphertext; composed of a vector "a"
 * and integer "b"
 */
class MKLWECiphertextImpl : public Serializable {
private:
    std::vector<NativeVector> m_a{};
    NativeInteger m_b{};
    NativeInteger m_p = 4;  // pt modulus

public:
    MKLWECiphertextImpl() = default;

    MKLWECiphertextImpl(const std::vector<NativeVector>& a, const NativeInteger& b) : m_a(a), m_b(b) {}

    MKLWECiphertextImpl(std::vector<NativeVector>&& a, NativeInteger b) noexcept : m_a(std::move(a)), m_b(b) {}

    MKLWECiphertextImpl(const MKLWECiphertextImpl& rhs) : m_a(rhs.m_a), m_b(rhs.m_b) {}

    MKLWECiphertextImpl(MKLWECiphertextImpl&& rhs) noexcept : m_a(std::move(rhs.m_a)), m_b(std::move(rhs.m_b)) {}

    MKLWECiphertextImpl& operator=(const MKLWECiphertextImpl& rhs) {
        m_a = rhs.m_a;
        m_b = rhs.m_b;
        return *this;
    }

    MKLWECiphertextImpl& operator=(MKLWECiphertextImpl&& rhs) noexcept {
        m_a = std::move(rhs.m_a);
        m_b = std::move(rhs.m_b);
        return *this;
    }

    const std::vector<NativeVector>& GetA() const {
        return m_a;
    }

    const std::vector<NativeVector> GetAneg() const {
        uint32_t k = m_a.size();
        auto mod = m_a[0].GetModulus();
        auto n = m_a[0].GetLength();
        std::vector<NativeVector> Aneg(k,NativeVector(n,mod));
        NativeVector zero(n,mod);
        for(uint32_t u=0;u<k;u++){
            Aneg[u] = zero.ModSub(m_a[u]);
        }
        return Aneg;
    }

    std::vector<NativeVector>& GetA() {
        return m_a;
    }

    const NativeInteger& GetA(std::size_t i, std::size_t j) const {
        return m_a[i][j];
    }

    NativeInteger& GetA(std::size_t i, std::size_t j) {
        return m_a[i][j];
    }

    const NativeInteger& GetB() const {
        return m_b;
    }

    NativeInteger& GetB() {
        return m_b;
    }

    uint32_t Getk() const {
        return m_a.size();
    }

    const NativeInteger& GetModulus() const {
        return m_a[0].GetModulus();
    }

    uint32_t GetLength() const {
        return m_a[0].GetLength();
    }

    const NativeInteger& GetptModulus() const {
        return m_p;
    }

    void SetA(const std::vector<NativeVector>& a) {
        m_a = a;
    }

    void SetB(const NativeInteger& b) {
        m_b = b;
    }

    // void SetModulus(const NativeInteger& mod) {
    //     m_a.ModEq(mod);
    //     m_a.SetModulus(mod);
    //     m_b.ModEq(mod);
    // }

    void SetptModulus(const NativeInteger& pmod) {
        m_p = pmod;
    }

    bool operator==(const MKLWECiphertextImpl& other) const {
        return m_a == other.m_a && m_b == other.m_b;
    }

    bool operator!=(const MKLWECiphertextImpl& other) const {
        return !(*this == other);
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("a", m_a));
        ar(::cereal::make_nvp("b", m_b));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW(deserialize_error, "serialized object version " + std::to_string(version) +
                                                 " is from a later version of the library");
        }

        ar(::cereal::make_nvp("a", m_a));
        ar(::cereal::make_nvp("b", m_b));
    }

    std::string SerializedObjectName() const override {
        return "MKLWECiphertext";
    }
    static uint32_t SerializedVersion() {
        return 1;
    }


};

}  // namespace lbcrypto

#endif  // _MKLWE_CIPHERTEXT_H_
