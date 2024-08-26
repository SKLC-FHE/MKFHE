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

/*
 * Custom Modifications:
 * - [This code is the implementation of the algorithm in the paper https://eprint.iacr.org/2023/1564]
 * 
 * This modified section follows the terms of the original BSD 2-Clause License.
 * Other modifications are provided under the terms of the BSD 2-Clause License.
 * See the BSD 2-Clause License text below:
 */



//==================================================================================
#ifndef _MKNTRU_ACC_XZDDF_H_
#define _MKNTRU_ACC_XZDDF_H_

// #include "rgsw-acc.h"
#include "mk-acc.h"

#include <memory>

using namespace std;
namespace lbcrypto {


class UniEncAccumulatorXZW final : public UniEncAccumulator {
public:
    UniEncAccumulatorXZW() = default;

    UniEncACCKey KeyGenAcc(const std::shared_ptr<UniEncCryptoParams>& params, 
                         const std::vector<NativePoly>& invskNTT,   const ConstMNTRUPrivateKey& MNTRUsk, const std::vector<NativePoly>& CRS) const override;
    void EvalAcc(const std::shared_ptr<UniEncCryptoParams>& params,ConstUniEncACCKey& ek,std::vector<std::vector<NativePoly>> Pkey,std::vector<NativePoly> skf, MKACCCiphertext& acc,
                 const std::vector<NativeVector>& ct) const override;

private:

    UniEncEvalKey KDMKeyGenXZW(const std::shared_ptr<UniEncCryptoParams>& params, const NativePoly& invskNTT,
                            const std::vector<NativePoly>& CRS, MNTRUPlaintext m) const;
    UniEncEvalKey KeyGenXZW(const std::shared_ptr<UniEncCryptoParams>& params, const NativePoly& invskNTT,
                            const std::vector<NativePoly>& CRS, MNTRUPlaintext m) const;                        

    UniEncEvalKey KeyGenAuto(const std::shared_ptr<UniEncCryptoParams>& params, const NativePoly& skNTT,
    const NativePoly& invskNTT, MNTRUPlaintext k) const;

    /**
     * @brief 
     * 
     * @param params 
     * @param d    d_i
     * @param f    f_i
     * @param index   
     * @param Pkey 
     * @param acc 
     */
    void HbProd(const std::shared_ptr<UniEncCryptoParams>& params, std::vector<NativePoly>& d,std::vector<NativePoly>& f, uint32_t index,std::vector<std::vector<NativePoly>> Pkey, 
                    MKACCCiphertext& acc) const;

    void AddToAccXZW(const std::shared_ptr<UniEncCryptoParams>& params, ConstUniEncEvalKey& ek1,ConstUniEncEvalKey& ek2, const NativeInteger& c,std::vector<std::vector<NativePoly>> Pkey, uint32_t index,
                    MKACCCiphertext& acc,std::vector<NativePoly> skf) const;
    
    void AddToAccXZW0(const std::shared_ptr<UniEncCryptoParams>& params, ConstUniEncEvalKey& ekstar,ConstUniEncEvalKey& ek1,ConstUniEncEvalKey& ek2, const NativeInteger& c,std::vector<std::vector<NativePoly>> Pkey, uint32_t index,
                    MKACCCiphertext& acc,std::vector<NativePoly> skf) const;
   
};

}  // namespace lbcrypto

#endif  // _MKNTRU_ACC_XZDDF_H_