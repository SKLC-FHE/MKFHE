
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




//==================================================================================

#ifndef _MKNTRU_FHE_H_
#define _MKNTRU_FHE_H_

#include "mk-ciphertext.h"
// #include "rgsw-acckey.h"
// #include "rgsw-cryptoparameters.h"


#include "mk-acckey.h"
#include "mk-cryptoparameters.h"


#include <vector>
#include <memory>

namespace lbcrypto {

class UniEncAccumulator {
public:
    UniEncAccumulator() = default;

    virtual UniEncACCKey KeyGenAcc(const std::shared_ptr<UniEncCryptoParams>& params,const std::vector<NativePoly>& invskNTT,  const ConstMNTRUPrivateKey& MNTRUsk, const std::vector<NativePoly>& CRS) const 
    {
        OPENFHE_THROW(not_implemented_error, "KeyGenACC operation not supported");
    }

    virtual UniEncACCKey KeyGenAcc(const std::shared_ptr<UniEncCryptoParams>& params,const std::vector<NativePoly>& invskNTT,  const ConstMKLWEPrivateKey& MKLWEsk, const std::vector<NativePoly>& CRS) const 
    {
        OPENFHE_THROW(not_implemented_error, "KeyGenACC operation not supported");
    }

    virtual void EvalAcc(const std::shared_ptr<UniEncCryptoParams>& params, ConstUniEncACCKey& ek,std::vector<std::vector<NativePoly>> Pkey,std::vector<NativePoly> skf,
                        MKACCCiphertext& acc, const std::vector<NativeVector>& ct) const {
            //std::cout<<"run EvalAcc in mk-acc.h"<<std::endl;
        OPENFHE_THROW(not_implemented_error, "ACC operation not supported");
    }

    void SignedDigitDecompose(const std::shared_ptr<UniEncCryptoParams>& params, const std::vector<NativePoly>& input,
                              std::vector<NativePoly>& output) const;

    void SignedDigitDecompose(const std::shared_ptr<UniEncCryptoParams>& params, const NativePoly& input,
                              std::vector<NativePoly>& output) const;
};
}  // namespace lbcrypto

#endif