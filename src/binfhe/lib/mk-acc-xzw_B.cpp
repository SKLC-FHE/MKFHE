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

#include "mk-acc-xzw_B.h"

#include <string>

namespace lbcrypto {

UniEncACCKey UniEncAccumulatorXZW_B::KeyGenAcc(const std::shared_ptr<UniEncCryptoParams>& params,
                                             const std::vector<NativePoly>& invskNTT,
                                             const ConstMNTRUPrivateKey& MNTRUsk,
                                             const std::vector<NativePoly>& CRS) const {
    // std::cout << "In mk acc xzw KeyGenAcc" << std::endl;
    std::vector<NativeVector> sv = MNTRUsk->GetF_col0();  


    uint32_t n = sv[0].GetLength();
    uint32_t k = sv.size();
    auto ek    = std::make_shared<UniEncACCKeyImpl>(k, 1, n + 1);


    for (uint32_t u = 0; u < k; u++) {
        auto& ek00 = (*ek)[u][0];  // evk
        //std::cout<<"u = "<<u<<std::endl;
        for (uint32_t i = 0; i < n; ++i) {
            //std::cout<<"i = "<<i<<std::endl;
            auto s = sv[u][i].ConvertToInt();
            //cout<<"s = "<<s<<endl;
            if (u == 0 && i == 0) {
                //std::cout<<"00"<<std::endl;
                ek00[i] = KDMKeyGenXZW(params, invskNTT[u], CRS, s == 1 ? 1 : 0);
                ek00[n] = KDMKeyGenXZW(params, invskNTT[u], CRS, 1);  //evk_1,0* = Enc(1/s_1)
            }
            else {
                //std::cout<<"11"<<std::endl;
                // std::cout<<"ek00[i]"<<ek00[i]<<std::endl;
                ek00[i] = KeyGenXZW(params, invskNTT[u], CRS, s == 1 ? 1 : 0);
                // std::cout<<"ek00[i]"<<ek00[i]<<std::endl;
            }
        }
    }

    return ek;
}

UniEncACCKey UniEncAccumulatorXZW_B::KeyGenAcc(const std::shared_ptr<UniEncCryptoParams>& params,
                                             const std::vector<NativePoly>& invskNTT,
                                             const ConstMKLWEPrivateKey& MKLWEsk,
                                             const std::vector<NativePoly>& CRS) const {
   
    std::vector<NativeVector> sv = MKLWEsk->GetElement();  
    uint32_t n = sv[0].GetLength();
    uint32_t k = sv.size();



    auto ek    = std::make_shared<UniEncACCKeyImpl>(k, 1, n + 1);
    for (uint32_t u = 0; u < k; u++) {
        auto& ek00 = (*ek)[u][0];  // evk
        for (uint32_t i = 0; i < n; ++i) {
            auto s = sv[u][i].ConvertToInt();
            if (u == 0 && i == 0) {
                ek00[i] = KDMKeyGenXZW(params, invskNTT[u], CRS, s == 1 ? 1 : 0);
                ek00[n] = KDMKeyGenXZW(params, invskNTT[u], CRS, 1);  //evk_1,0* = Enc(1/s_1)
            }
            else {
                ek00[i] = KeyGenXZW(params, invskNTT[u], CRS, s == 1 ? 1 : 0); 
            }
        }
    }
    return ek;
}

void UniEncAccumulatorXZW_B::EvalAcc(const std::shared_ptr<UniEncCryptoParams>& params, ConstUniEncACCKey& ek,
                                   std::vector<std::vector<NativePoly>> Pkey, std::vector<NativePoly> skf,
                                   MKACCCiphertext& acc, const std::vector<NativeVector>& ct) const {
    // const auto& B = Pkey;
    // std::cout << "In UniEncAccumulatorXZW_B EvalACC" << std::endl;
    uint32_t k  = ct.size();
    uint32_t n  = ct[0].GetLength();
   // auto mod    = ct[0].GetModulus();  //q
    // auto MbyMod = NativeInteger(2 * params->GetN()) / mod;
//  auto N = params->GetN();
   

   
    for (uint32_t u = 0; u < k; u++) {
        for (size_t i = 0; i < n; ++i) {
            if (u == 0 && i == 0) {
                // cout << "u = "<<u<<" i = "<<i << endl;
                AddToAccXZW0(params, (*ek)[u][0][n], (*ek)[u][0][i], ct[u][i], Pkey, u, acc,skf);
                
            }

            else {
                // cout << "u = "<<u<<" i = "<<i << endl;
                AddToAccXZW(params, (*ek)[u][0][i], ct[u][i], Pkey, u, acc,skf);

              
            }
        }
    }
   
}

UniEncEvalKey UniEncAccumulatorXZW_B::KeyGenXZW(const std::shared_ptr<UniEncCryptoParams>& params,
                                              const NativePoly& invskNTT, const std::vector<NativePoly>& CRS,
                                              MNTRUPlaintext m) const {
    const auto& Gpow       = params->GetGPower();
    const auto& polyParams = params->GetPolyParams();
    auto N                 = params->GetN();
    //std::cout<<"In KeyGenXZW:"<<std::endl;
    NativeInteger Q{params->GetQ()};
    uint32_t digitsG{(params->GetDigitsG() - 1)};
   
    TernaryUniformGeneratorImpl<NativeVector> tug;
    NativePoly skrPoly(polyParams);
    usint hw = 2;
    NativeVector r = tug.GenerateVector(N, Q,hw);
    
    skrPoly.SetValues(r, Format::COEFFICIENT);

    skrPoly.SetFormat(Format::EVALUATION);
    

    UniEncEvalKeyImpl result(digitsG, 2);  //  (d,f) R^d x R^d


    for (uint32_t i = 0; i < digitsG; ++i) {
   
        result[i][0] = NativePoly(params->GetDgg(), polyParams, Format::COEFFICIENT);
        result[i][1] = NativePoly(params->GetDgg(), polyParams, Format::COEFFICIENT);
        result[i][1].SetFormat(Format::EVALUATION);
        result[i][0].SetFormat(Format::EVALUATION);


        NativeVector gd_vec(N, Q);
        gd_vec[0] = Gpow[i + 1];
       // cout << "B_i" << Gpow[i + 1] << endl;
        NativePoly gd(polyParams);
        gd.SetValues(gd_vec, Format::COEFFICIENT);
        gd.SetFormat(Format::EVALUATION);
        result[i][1] = result[i][1] + gd * skrPoly;  // e_1 + r*g
        result[i][1] = result[i][1] * invskNTT;      //  ( e_1 + r * g) * s_inv

        if (m==1)  // 1 or 0
        {
            result[i][0] = result[i][0] + gd;
        }
        result[i][0] = result[i][0] + skrPoly[i] * CRS[i];  //  r*CRS +  e0 + B^i
    }

   



    return std::make_shared<UniEncEvalKeyImpl>(result);
}

UniEncEvalKey UniEncAccumulatorXZW_B::KDMKeyGenXZW(const std::shared_ptr<UniEncCryptoParams>& params,
                                                 const NativePoly& invskNTT, const std::vector<NativePoly>& CRS,
                                                 MNTRUPlaintext m) const {
    const auto& Gpow       = params->GetGPower();
    const auto& polyParams = params->GetPolyParams();
    auto N                 = params->GetN();
    NativeInteger Q{params->GetQ()};
    uint32_t digitsG{(params->GetDigitsG() - 1)};

    TernaryUniformGeneratorImpl<NativeVector> tug;
    NativePoly skrPoly(polyParams);
    usint hw=2;
    NativeVector r = tug.GenerateVector(N, Q,hw);
    skrPoly.SetValues(r, Format::COEFFICIENT);
   
    skrPoly.SetFormat(Format::EVALUATION);
    

    UniEncEvalKeyImpl result(digitsG, 2);  //  (d,f) R^d x R^d

    //UniEncEvalKeyImpl result;
    for (uint32_t i = 0; i < digitsG; ++i) {
 
        result[i][0] = NativePoly(params->GetDgg(), polyParams, Format::COEFFICIENT);
       // cout<< result[i][0] <<endl;
        result[i][1] = NativePoly(params->GetDgg(), polyParams, Format::COEFFICIENT);
        result[i][1].SetFormat(Format::EVALUATION);
        result[i][0].SetFormat(Format::EVALUATION);


        NativeVector gd_vec(N, Q);
        gd_vec[0] = Gpow[i + 1];
        NativePoly gd(polyParams);
        gd.SetValues(gd_vec, Format::COEFFICIENT);
        gd.SetFormat(Format::EVALUATION);
        result[i][1] = result[i][1] + gd * skrPoly;  // e_1 + r*g
        result[i][1] = result[i][1] * invskNTT;      //  ( e_1 + r * g) * s_inv

        if (m)  // 1 or 0
        {
            result[i][0] = result[i][0] + gd * invskNTT;
        }
        result[i][0] = result[i][0] + skrPoly[i] * CRS[i];  //  r*CRS +  e0 + B^i
    }
    return std::make_shared<UniEncEvalKeyImpl>(result);
}

//HbProd
void UniEncAccumulatorXZW_B::HbProd(const std::shared_ptr<UniEncCryptoParams>& params, std::vector<NativePoly>& d,
                                  std::vector<NativePoly>& f, uint32_t index, std::vector<std::vector<NativePoly>> Pkey,
                                  MKACCCiphertext& acc) const {
    
    std::vector<NativePoly> ct(acc->GetElements());  //(c1,...,c_k)
    auto k = params->Getk();


    for (uint32_t u = 0; u < k; u++) {
        ct[u].SetFormat(Format::COEFFICIENT);
      
    }

    uint32_t digitsG{(params->GetDigitsG() - 1)};  // d-1
    
    // std::cout<<"0"<<std::endl;
    auto polyParams = params->GetPolyParams();

    // uint32_t MInt{2 * params->GetN()};
    // NativeInteger M{MInt};
    // std::cout<<"1"<<std::endl;
    NativePoly sumV(polyParams);
    for (uint32_t u = 0; u < k; u++) {
        std::vector<NativePoly> dct(digitsG, NativePoly(params->GetPolyParams(), Format::COEFFICIENT, true));
        SignedDigitDecompose(params, ct[u], dct);  // 
       

#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(digitsG))
        for (uint32_t i = 0; i < digitsG; ++i)
            dct[i].SetFormat(Format::EVALUATION);

        NativePoly uj(dct[0] * d[0]);
        NativePoly v(dct[0] * Pkey[u][0]);
        for (uint32_t i = 1; i < digitsG; ++i) {
            uj += (dct[i] * d[i]);  //< g_inv(c) ,  d_i >
            v += (dct[i] * Pkey[u][i]);
        }
        sumV += v;
        acc->GetElements()[u] = uj;
    }

    sumV.SetFormat(Format::COEFFICIENT);
    std::vector<NativePoly> dct(digitsG, NativePoly(params->GetPolyParams(), Format::COEFFICIENT, true));
    SignedDigitDecompose(params, sumV, dct);  

#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(digitsG))
    for (uint32_t i = 0; i < digitsG; ++i)
        dct[i].SetFormat(Format::EVALUATION);

    for (uint32_t u = 0; u < k; u++) {
        if (index == u) {
            NativePoly w(dct[0] * f[0]);
            for (uint32_t i = 1; i < digitsG; ++i) {
                w += (dct[i] * f[i]);  //< g_inv(v) ,  f_i >
            }
            acc->GetElements()[index] += w;
        }
    }
}

void UniEncAccumulatorXZW_B::AddToAccXZW(const std::shared_ptr<UniEncCryptoParams>& params, ConstUniEncEvalKey& ek1,
                                       const NativeInteger& c,
                                       std::vector<std::vector<NativePoly>> Pkey, uint32_t index,
                                       MKACCCiphertext& acc,std::vector<NativePoly> skf) const {
   // std::cout << "In UniEncAccumulatorXZW_B AddToAccXZW" << std::endl;
    uint32_t MInt{2 * params->GetN()};
    NativeInteger M{MInt};
   uint32_t indexPos{c.ConvertToInt<uint32_t>()};
//std::cout << "indexPos = " << indexPos << std::endl;
    const NativePoly& monomial = params->GetMonomial(indexPos == MInt ? 0 : indexPos);

    // NativePoly Xc = monomial;
    // std::cout << "Xc -1 = " << Xc << std::endl;
    // Xc.SetFormat(COEFFICIENT);
    // std::cout << "Xc - 1 = " << Xc << std::endl;
    // Xc.SetFormat(EVALUATION);

    // uint32_t indexNeg{NativeInteger(0).ModSubFast(c, M).ConvertToInt<uint32_t>()};
    // const NativePoly& monomialNeg = params->GetMonomial(indexNeg == MInt ? 0 : indexNeg);

    // NativePoly Xcneg = monomialNeg;
    // std::cout << "Xcneg -1 = " << Xcneg << std::endl;
    // Xcneg.SetFormat(COEFFICIENT);
    // std::cout << "Xcneg - 1 = " << Xcneg << std::endl;
    // Xcneg.SetFormat(EVALUATION);

    uint32_t digitsG{params->GetDigitsG() - 1};
    auto polyParams = params->GetPolyParams();
    auto k          = params->Getk();

    const std::vector<std::vector<NativePoly>>& ev1(ek1->GetElements());
    std::vector<NativePoly> d(digitsG, NativePoly(polyParams));
    std::vector<NativePoly> f(digitsG, NativePoly(polyParams));
    for (uint32_t i = 0; i < digitsG; i++) {
        d[i] = ev1[i][0] ;
        f[i] = ev1[i][1] ;
    }

    MKACCCiphertext acctemp = std::make_shared<MKACCCiphertextImpl>(*acc);


    for (uint32_t u = 0; u < k; u++) {
        acctemp->GetElements()[u] = acctemp->GetElements()[u] * monomial;
    }

    // HbProd((X^c - 1)ACC,PK,u,evk)
    HbProd(params, d, f, index, Pkey, acctemp);
    for (uint32_t u = 0; u < k; u++) {
        acc->GetElements()[u] = acc->GetElements()[u] + acctemp->GetElements()[u];
    }
}

void UniEncAccumulatorXZW_B::AddToAccXZW0(const std::shared_ptr<UniEncCryptoParams>& params, ConstUniEncEvalKey& ekstar,
                                        ConstUniEncEvalKey& ek1, const NativeInteger& c,
                                        std::vector<std::vector<NativePoly>> Pkey, uint32_t index,
                                        MKACCCiphertext& acc,std::vector<NativePoly> skf) const {
  //  std::cout << "In UniEncAccumulatorXZW_B AddToAccXZW0" << std::endl;
    uint32_t MInt{2 * params->GetN()};
    NativeInteger M{MInt};
    uint32_t indexPos{c.ConvertToInt<uint32_t>()};
  //  std::cout << "indexPos = " << indexPos << std::endl;

    const NativePoly& monomial = params->GetMonomial(indexPos == MInt ? 0 : indexPos);
    // NativePoly Xc              = monomial;
    // std::cout << "Xc = " << Xc << std::endl;
    // Xc.SetFormat(COEFFICIENT);
    // std::cout << "Xc = " << Xc << std::endl;
    // Xc.SetFormat(EVALUATION);

    // uint32_t indexNeg{NativeInteger(0).ModSubFast(c, M).ConvertToInt<uint32_t>()};
    // const NativePoly& monomialNeg = params->GetMonomial(indexNeg == MInt ? 0 : indexNeg);
    uint32_t digitsG{params->GetDigitsG() - 1};
    auto polyParams = params->GetPolyParams();

    const std::vector<std::vector<NativePoly>>& evs(ekstar->GetElements());
    const std::vector<std::vector<NativePoly>>& ev1(ek1->GetElements());
   // const std::vector<std::vector<NativePoly>>& ev2(ek2->GetElements());
    //std::cout<<"d,f"<<std::endl;
    std::vector<NativePoly> d(digitsG, NativePoly(polyParams));
    std::vector<NativePoly> f(digitsG, NativePoly(polyParams));
    // NativePoly temp1(polyParams);
    // NativePoly temp2(polyParams);
    //std::cout<<"d,f"<<std::endl;

    for (uint32_t i = 0; i < digitsG; i++) {
        d[i] = evs[i][0] + ev1[i][0] * monomial ;
        f[i] = evs[i][1] + ev1[i][1] * monomial ;
    }



    // for (uint32_t i = 0; i < digitsG; i++) {
    //     d[i].SetFormat(EVALUATION);
    //     f[i].SetFormat(EVALUATION);
    // }


    HbProd(params, d, f, index, Pkey, acc);
}

};  // namespace lbcrypto
