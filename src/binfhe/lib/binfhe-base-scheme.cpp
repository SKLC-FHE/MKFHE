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


#include "binfhe-base-scheme.h"

#include <string>

namespace lbcrypto {

// wrapper for KeyGen methods
RingGSWBTKey BinFHEScheme::KeyGen(const std::shared_ptr<BinFHECryptoParams>& params, ConstLWEPrivateKey& LWEsk,
                                  KEYGEN_MODE keygenMode = SYM_ENCRYPT) const {
    const auto& LWEParams = params->GetLWEParams();

    RingGSWBTKey
        ek;  
    LWEPrivateKey skN;  
    if (keygenMode == SYM_ENCRYPT) {
        skN = LWEscheme->KeyGen(LWEParams->GetN(), LWEParams->GetQ());
    }
    else if (keygenMode == PUB_ENCRYPT) {
        ConstLWEKeyPair kpN = LWEscheme->KeyGenPair(LWEParams);
        skN                 = kpN->secretKey;
        ek.Pkey             = kpN->publicKey;
    }
    else {
        OPENFHE_THROW(config_error, "Invalid KeyGen mode");
    }
    /*-----------KSkey-------------*/
    ek.KSkey = LWEscheme->KeySwitchGen(LWEParams, LWEsk, skN);

    const auto& RGSWParams = params->GetRingGSWParams();
    const auto& polyParams = RGSWParams->GetPolyParams(); 
    NativePoly skNPoly(polyParams);
    skNPoly.SetValues(skN->GetElement(), Format::COEFFICIENT);
    skNPoly.SetFormat(Format::EVALUATION);
    /*-----------BSkey-------------*/
    ek.BSkey = ACCscheme->KeyGenAcc(RGSWParams, skNPoly, LWEsk);

    return ek;
}

VectorNTRUBTKey BinFHEScheme::NKeyGen(const std::shared_ptr<BinFHECryptoParams>& params, ConstLWEPrivateKey& LWEsk,
                                      KEYGEN_MODE keygenMode = SYM_ENCRYPT) const {
    const auto& LWEParams = params->GetLWEParams();
    VectorNTRUBTKey ek; 

    const auto& VNTRUParams = params->GetVectorNTRUParams();
    const auto& polyParams  = VNTRUParams->GetPolyParams();  
    uint32_t Q{VNTRUParams->GetQ().ConvertToInt<uint32_t>()};
    uint32_t N{VNTRUParams->GetN()};

    NativeVector NatVec(N, Q);
    NativeVector NatVec_inv(N, Q);
    Get_invertible_NativeVector(NatVec, NatVec_inv, Q, N, GAUSSIAN);
    LWEPrivateKey LWEskN = std::make_shared<LWEPrivateKeyImpl>(LWEPrivateKeyImpl(NatVec));

    ek.KSkey = LWEscheme->KeySwitchGen(LWEParams, LWEsk, LWEskN);

    NativePoly skNPoly(polyParams);
    skNPoly.SetValues(NatVec, Format::COEFFICIENT);
    NativePoly invskNPoly(polyParams);
    invskNPoly.SetValues(NatVec_inv, Format::COEFFICIENT);
    skNPoly.SetFormat(Format::EVALUATION);
    invskNPoly.SetFormat(Format::EVALUATION);

    ek.BSkey = NACCscheme->KeyGenAcc(VNTRUParams, skNPoly, invskNPoly, LWEsk);

    return ek;
}

void Get_invertible_NativeVector(NativeVector& NatVec, NativeVector& NatVec_inv, uint32_t q_boot, uint32_t N,SecretKeyDist keyDist) {
   
    uniform_int_distribution<int> ternary_sampler(-1,1);
 
    normal_distribution<double> gaussian_sampler(0.0, 0.5);

    default_random_engine rand_engine(std::chrono::system_clock::now().time_since_epoch().count());

    std::vector<int> vec     = std::vector<int>(N, 0);
    std::vector<int> vec_inv = std::vector<int>(N, 0);

    uint32_t half_q_boot = q_boot / 2;
    //polynomial with the coefficient vector vec (will be generated later)
    ZZ_pX poly;
    //element of Z_(q_boot)
    ZZ_p coef;
    coef.init(ZZ(q_boot));
    //the inverse of poly modulo poly_mod (will be generated later)
    ZZ_pX inv_poly;
    //random sampling
    //int sum = 0;
    while (true) {
        //create the polynomial with the coefficient vector of the desired form
        if(keyDist == GAUSSIAN){
            SetCoeff(poly, 0, gaussian_sampler(rand_engine));
        }
        else{
            SetCoeff(poly, 0, ternary_sampler(rand_engine));
        }
        
        for (uint32_t i = 1; i < N; i++) {
            if(keyDist == GAUSSIAN){
                coef = gaussian_sampler(rand_engine);
            }
            else{
                coef = ternary_sampler(rand_engine);
            }
            
            // if(coef == 0)
            // {
            //     sum++;
            // }
            SetCoeff(poly, i, coef);
        }
        //cout<<double(sum)/N<<endl;
        //test invertibility
        try {
            // static ZZ_pX get_def_poly()
            ZZ_pX def_poly;
            ZZ_p coef;
            coef.init(ZZ(q_boot));
            coef = 1;
            SetCoeff(def_poly, 0, coef);
            SetCoeff(def_poly, N, coef);

            InvMod(inv_poly, poly, def_poly);
            break;
        }
        catch (...) {
            //cout << "Polynomial " << poly << " isn't a unit" << endl;
            continue;
        }
    }
    uint32_t tmp_coef;
    for (uint32_t i = 0; i <= deg(poly); i++) {
        tmp_coef = conv<long>(poly[i]);
        if (tmp_coef > half_q_boot)
            tmp_coef -= q_boot;
        vec[i] = tmp_coef;
    }

    for (uint32_t i = 0; i <= deg(inv_poly); i++) {
        tmp_coef = conv<long>(inv_poly[i]);
        if (tmp_coef > half_q_boot)
            tmp_coef -= q_boot;
        vec_inv[i] = tmp_coef;
    }
    // vector<int> to NativePoly
    for (uint32_t i = 0; i < N; i++) {
        int32_t v     = vec[i];
        int32_t v_inv = vec_inv[i];
        if (v < 0)
            NatVec[i] = q_boot - typename NativeVector::Integer(-v);
        else
            NatVec[i] = typename NativeVector::Integer(v);
        if (v_inv < 0)
            NatVec_inv[i] = q_boot - typename NativeVector::Integer(-v_inv);
        else
            NatVec_inv[i] = typename NativeVector::Integer(v_inv);
    }
}


UniEncBTKey BinFHEScheme::MKKeyGen(const std::shared_ptr<BinFHECryptoParams>& params,ConstMNTRUPrivateKey& MNTRUsk,KEYGEN_MODE keygenMode = SYM_ENCRYPT) const {
    UniEncBTKey ek;
    const auto& MNTRUParams = params->GetMatrixNTRUParams();
    const auto& UniEncParams = params->GetUniEncParams();
    const auto& polyParams  = UniEncParams->GetPolyParams(); 
    NativeInteger Q{UniEncParams->GetQ()};
    uint32_t uint_Q{Q.ConvertToInt<uint32_t>()};
    uint32_t N{UniEncParams->GetN()};
    uint32_t k{MNTRUParams->Getk()};
    std::vector<NativePoly> CRS{UniEncParams->GetCRS()};
    uint32_t digitsG{UniEncParams->GetDigitsG()-1};

    
    std::vector<NativeVector> UniEncsk;
    std::vector<NativePoly> skNPoly_k;
    std::vector<NativePoly> invskNPoly_k;
    for(uint32_t i=0;i<k;i++)
    {
        NativeVector NatVec(N, Q);   //s
        NativeVector NatVec_inv(N, Q);  //s_inv
        Get_invertible_NativeVector(NatVec, NatVec_inv, uint_Q, N, GAUSSIAN);
       
        NativePoly skNPoly(polyParams);
        skNPoly.SetValues(NatVec, Format::COEFFICIENT);
        NativePoly invskNPoly(polyParams);
        invskNPoly.SetValues(NatVec_inv, Format::COEFFICIENT);
        skNPoly.SetFormat(Format::EVALUATION);
        invskNPoly.SetFormat(Format::EVALUATION);
        UniEncsk.push_back(NatVec); 
        skNPoly_k.push_back(skNPoly);
        invskNPoly_k.push_back(invskNPoly);
    }
    ek.f = skNPoly_k;
    ek.fvec = UniEncsk; 
    ek.F_col0 = MNTRUsk->GetF_col0(); 

   
    ek.KSkey2 = MNTRUscheme->KeySwitchGen2(MNTRUParams, MNTRUsk, UniEncsk);

    // auto Nd = ek.KSkey->GetElements()[0].size();
    // auto n = ek.KSkey->GetElements()[0][0].GetLength();
    // for(uint32_t i=0;i<Nd;i++){
    //     for(uint32_t j=0;j<n;j++){
    //         cout<<ek.KSkey->GetElements()[0][i][j]<<"\t";
    //     }
    //     cout<<endl;
    // }
    // std::cout<<ek.KSkey->GetElements_coli(0)[0]<<endl;;



    
    std::vector<NativePoly> e(digitsG,NativePoly(polyParams));
    //TernaryUniformGeneratorImpl<NativeVector> tug;
    std::vector<std::vector<NativePoly>> Pkey(k,std::vector<NativePoly>(digitsG,NativePoly(polyParams,EVALUATION)));
    for(uint32_t u=0;u<k;u++)
    {
        //std::cout<<"u = "<<u<<std::endl;
        for(uint32_t i=0; i<digitsG ;i++)
        {
            //std::cout<<"i = "<<i<<std::endl;
            
            // NativeVector e_vec = tug.GenerateVector(N, Q);
            NativeVector e_vec = UniEncParams->GetDgg().GenerateVector(N,Q);
            //std::cout<<"e_vec.len = "<<e_vec.GetLength()<<std::endl;
            e[i].SetValues(e_vec, Format::COEFFICIENT);
            e[i].SetFormat(Format::EVALUATION);
            //std::cout<<"1"<<std::endl;
            Pkey[u][i] = e[i] - CRS[i]*skNPoly_k[u] ;
        }
    }
    ek.Pkey = Pkey;
    // std::cout<<"In base scheme KeyGenAcc:"<<std::endl;
    /*------------------------BSkey-----------------------*/
    ek.BSkey = UniEncACCscheme->KeyGenAcc(UniEncParams,invskNPoly_k, MNTRUsk,CRS);


    return ek;
}


UniEncBTKey BinFHEScheme::MKKeyGen(const std::shared_ptr<BinFHECryptoParams>& params,ConstMKLWEPrivateKey& MKLWEsk,KEYGEN_MODE keygenMode = SYM_ENCRYPT) const {
    UniEncBTKey ek;
    const auto& MKLWEParams = params->GetMKLWEParams();
    const auto& UniEncParams = params->GetUniEncParams();
    const auto& polyParams  = UniEncParams->GetPolyParams(); 
    NativeInteger Q{UniEncParams->GetQ()};
    uint32_t uint_Q{Q.ConvertToInt<uint32_t>()};
    uint32_t N{UniEncParams->GetN()};
    uint32_t k{UniEncParams->Getk()};
    std::vector<NativePoly> CRS{UniEncParams->GetCRS()};
    uint32_t digitsG{UniEncParams->GetDigitsG()-1};

    std::vector<NativeVector> UniEncsk;
    std::vector<NativePoly> skNPoly_k;
    std::vector<NativePoly> invskNPoly_k;
    for(uint32_t i=0;i<k;i++)
    {
        NativeVector NatVec(N, Q);   //s
        NativeVector NatVec_inv(N, Q);  //s_inv
        Get_invertible_NativeVector(NatVec, NatVec_inv, uint_Q, N, UNIFORM_TERNARY);

        NativePoly skNPoly(polyParams);
        skNPoly.SetValues(NatVec, Format::COEFFICIENT);
        NativePoly invskNPoly(polyParams);
        invskNPoly.SetValues(NatVec_inv, Format::COEFFICIENT);
        skNPoly.SetFormat(Format::EVALUATION);
        invskNPoly.SetFormat(Format::EVALUATION);
        UniEncsk.push_back(NatVec); //
        skNPoly_k.push_back(skNPoly);
        invskNPoly_k.push_back(invskNPoly);
    }
    ek.f = skNPoly_k;
    ek.fvec = UniEncsk; 
    ek.lwesk = MKLWEsk->GetElement(); 
    /*------------------------KSK-----------------------*/
    // std::cout<<"In base scheme KeySwitchGen:"<<std::endl;
    ek.LKSkey = MKLWEscheme->KeySwitchGen(MKLWEParams, MKLWEsk, UniEncsk);
    /*------------------------b = -CRS*s + e -----------------------*/
    // std::cout<<"In base scheme b:"<<std::endl;
    std::vector<NativePoly> e(digitsG,NativePoly(polyParams));
    //TernaryUniformGeneratorImpl<NativeVector> tug;
    std::vector<std::vector<NativePoly>> Pkey(k,std::vector<NativePoly>(digitsG,NativePoly(polyParams,EVALUATION)));
    for(uint32_t u=0;u<k;u++)
    {
        for(uint32_t i=0; i<digitsG ;i++)
        {
            // NativeVector e_vec = tug.GenerateVector(N, Q);
            NativeVector e_vec = UniEncParams->GetDgg().GenerateVector(N,Q);
            e[i].SetValues(e_vec, Format::COEFFICIENT);
            e[i].SetFormat(Format::EVALUATION);
            Pkey[u][i] = e[i] - CRS[i]*skNPoly_k[u] ;
        }
    }
    ek.Pkey = Pkey;
 /*------------------------BSkey-----------------------*/
    ek.BSkey = UniEncACCscheme->KeyGenAcc(UniEncParams,invskNPoly_k, MKLWEsk,CRS);


    return ek;
}

MNTRUCiphertext BinFHEScheme::ctGateGen(const std::shared_ptr<BinFHECryptoParams>& params,ConstMNTRUPrivateKey& sk,const BINGATE gate) const{
    if(gate != NAND)
        OPENFHE_THROW(config_error, "Support NAND gate Only");

    const auto& MNTRUParams = params->GetMatrixNTRUParams();
    auto mod = MNTRUParams->Getq();
    uint32_t n = sk->GetLength();
    uint32_t k = sk->Getk();
    //std::vector<std::vector<NativeVector>> F_inv = sk->GetF_inv();
    std::vector<NativeVector> c(k,NativeVector(n,mod));

    for(uint32_t i=0;i<k;i++)
    {
        NativeVector e = MNTRUParams->GetDgg().GenerateVector(n,mod);
        //NativeVector e(n,mod);
        if(i==0)
        {   
            e[0].ModAddFastEq(5*mod/8,mod);//e + 5q/8
        }
        
        for(uint32_t j=0;j<n;j++)
        {
            NativeVector F_inv = sk->GetF_inv_coli(j)[i];
            F_inv.SwitchModulus(mod);
            //NativeVector
            NativeVector temp = e.ModMul(F_inv);
            NativeInteger sum(0);
            for(uint32_t l=0;l<n;l++)
            {
                sum.ModAddEq(temp[l],mod);
            }
            c[i][j] = sum;
        }
    }
    auto ct = std::make_shared<MNTRUCiphertextImpl>(MNTRUCiphertextImpl(std::move(c)));
    return ct;
}



MKLWECiphertext BinFHEScheme::EvalBinGate(const std::shared_ptr<BinFHECryptoParams>& params, BINGATE gate,
const UniEncBTKey& EK, ConstMKLWECiphertext& ct1,ConstMKLWECiphertext& ct2) const {
    if (ct1 == ct2)
        OPENFHE_THROW(config_error, "Input ciphertexts should be independant");
    // std::cout<<"---In BinFHEScheme EvalBinGate---"<<std::endl;
    MKLWECiphertext ctprep = std::make_shared<MKLWECiphertextImpl>(*ct1);

    const auto& MKLWEParams = params->GetMKLWEParams();
    auto n = MKLWEParams->Getn();
    // std::cout<<"n = "<<n<<std::endl;
    uint32_t q = MKLWEParams->Getq().ConvertToInt<uint32_t>();
    // std::cout<<"q = "<<q<<std::endl;
    auto k = MKLWEParams->Getk();
    // std::cout<<"k = "<<k<<std::endl;  

 
    std::vector<NativeVector> zero(k,NativeVector(n,q));
    NativeInteger temp_b= 5*q/8;
    MKLWECiphertext ct_temp = std::make_shared<MKLWECiphertextImpl>(MKLWECiphertextImpl(std::move(zero), temp_b.Mod(q)));

    MKLWEscheme->EvalAddEq(ctprep,ct2);
    MKLWEscheme->EvalSubEq(ct_temp,ctprep);  


   
    auto M = typename NativeVector::Integer(MKLWEParams->GetN()*2); ;
    auto ctMS1 = MKLWEscheme->ModSwitch(M, ct_temp);
    // cout<<"qKS = "<<qKS<<endl;
    // cout<<"7/8 * qKS = "<<7*qKS/8<<endl;
    // cout<<"1/8 * qKS = "<<1*qKS/8<<endl;
    // NativeInteger inner22(0);
    // auto bbb = ctMS1->GetB();
    // for(uint32_t u=0;u<k;u++){
    //     auto sk = EK.lwesk[u];
    //     //cout<<"sk = "<<sk<<endl;
    //     sk.SwitchModulus(M);
    //     // cout<<"u = "<<u<<endl;
    //     // cout<<"sk = "<<sk<<endl;
    //     // cout<<"ctMS = "<<ctMS->GetA()[u]<<endl;
    //     NativeVector temp = ctMS1->GetA()[u].ModMul(sk);
    //     NativeInteger sum(0);
    //     for (uint32_t l = 0; l < n; l++) {
    //         //std::cout<<"Point 444"<<std::endl;
    //         sum.ModAddEq(temp[l], M);  //sum = sum + temp[l]
    //     }
    //     inner22.ModAddEq(sum, M);
    // }
    // bbb.ModSubEq(inner22,M);
    // cout<<"0,1: 3/4N + rounding err ; 0,0: 5/4N  + rounding err ; 1,1: 1/4N  + rounding err. "<<bbb<<endl;
    // bbb.ModAddFastEq((M / (4)), M);

    // auto mmm = ((NativeInteger(2) * bbb) / M).ConvertToInt();
    // cout<<"mmmm= "<<mmm<<endl;


  //  clock_t bs = clock();
    MKACCCiphertext acc = BootstrapGateCore(params, gate, EK.BSkey,EK.Pkey,EK.f ,ctMS1);  
  //  std::cout<<"\t bootstrapping:\t" << float(clock()-bs)*1000/CLOCKS_PER_SEC<<"ms" << std::endl;


  
    std::vector<NativePoly>& accVec{acc->GetElements()};
    std::vector<NativeVector> accExt(k);
    for(uint32_t u=0;u<k;u++)
    {
        accVec[u] = accVec[u].Transpose();
        accVec[u].SetFormat(Format::COEFFICIENT);
        accExt[u] = accVec[u].GetValues();
        //std::cout<<" accExt[u] ="<< accExt[u] <<std::endl;
    } 
    NativeInteger Q{MKLWEParams->GetQ()};
    NativeInteger b{(Q >> 3) + 1};
    // cout<<"Q/8"<<b<<endl;
  //  clock_t ext = clock();
    auto ctExt = std::make_shared<MKLWECiphertextImpl>(std::move(accExt),std::move(b));  
   // std::cout<<"\t Ext:\t" << float(clock()-ext)*1000/CLOCKS_PER_SEC<<"ms" << std::endl;

    
    auto ctMS = MKLWEscheme->ModSwitch(MKLWEParams->GetqKS(), ctExt);
   
     auto ctKS = MKLWEscheme->KeySwitch(MKLWEParams, EK.LKSkey, ctMS);
     return ctKS;
   // return ct_temp;
}



MNTRUCiphertext BinFHEScheme::EvalBinGate(const std::shared_ptr<BinFHECryptoParams>& params, BINGATE gate,
                                        const UniEncBTKey& EK, ConstMNTRUCiphertext& ct1,
                                        ConstMNTRUCiphertext& ct2,
                                        ConstMNTRUCiphertext& ctNAND) const {
    if (ct1 == ct2)
        OPENFHE_THROW(config_error, "Input ciphertexts should be independant");
    // std::cout<<"In BinFHEScheme EvalBinGate"<<std::endl;
    MNTRUCiphertext ctprep = std::make_shared<MNTRUCiphertextImpl>(*ct1);

    const auto& MNTRUParams = params->GetMatrixNTRUParams();
    // auto n = MNTRUParams->Getn();
    // std::cout<<"n = "<<n<<std::endl;
    // uint32_t q = MNTRUParams->Getq().ConvertToInt<uint32_t>();
    // std::cout<<"q = "<<q<<std::endl;
    auto k = MNTRUParams->Getk();
    // std::cout<<"k = "<<k<<std::endl; 


    MNTRUCiphertext ct_temp = std::make_shared<MNTRUCiphertextImpl>(*ctNAND);



    MNTRUscheme->EvalAddEq(ctprep,ct2);
    MNTRUscheme->EvalSubEq(ct_temp,ctprep);  

    MKACCCiphertext acc = BootstrapGateCore(params, gate, EK.BSkey,EK.Pkey,EK.f ,ct_temp);  

 
    
    

    std::vector<NativePoly>& accVec{acc->GetElements()};
    std::vector<NativeVector> accExt(k);
    for(uint32_t u=0;u<k;u++)
    {
        accVec[u] = accVec[u].Transpose();
        accVec[u].SetFormat(Format::COEFFICIENT);
        accExt[u] = accVec[u].GetValues();
        //std::cout<<" accExt[u] ="<< accExt[u] <<std::endl;
    } 
    NativeInteger Q{MNTRUParams->GetQ()};
    auto ctExt = std::make_shared<MNTRUCiphertextImpl>(std::move(accExt));


    auto ctMS = MNTRUscheme->ModSwitch(MNTRUParams->GetqKS(), ctExt);
   
        auto ctKS = MNTRUscheme->KeySwitch2(MNTRUParams, EK.KSkey2, ctMS);
    return ctKS;
}


LWECiphertext BinFHEScheme::EvalBinGate(const std::shared_ptr<BinFHECryptoParams>& params, BINGATE gate,
                                        const VectorNTRUBTKey& EK, ConstLWECiphertext& ct1,
                                        ConstLWECiphertext& ct2) const {
    if (ct1 == ct2)
        OPENFHE_THROW(config_error, "Input ciphertexts should be independant");

    // By default, we compute XOR/XNOR using a combination of AND, OR, and NOT gate
    if ((gate == XOR) || (gate == XNOR)) {
        const auto& ctAND1 = EvalBinGate(params, AND, EK, ct1, EvalNOT(params, ct2));
        const auto& ctAND2 = EvalBinGate(params, AND, EK, EvalNOT(params, ct1), ct2);
        const auto& ctOR   = EvalBinGate(params, OR, EK, ctAND1, ctAND2);

        // NOT is free so there is not cost to do it an extra time for XNOR
        return (gate == XOR) ? ctOR : EvalNOT(params, ctOR);
    }

    LWECiphertext ctprep = std::make_shared<LWECiphertextImpl>(*ct1);

  
    auto n = params->GetLWEParams()->Getn();
    NativeVector zero(n,0);
    uint32_t q = params->GetLWEParams()->Getq().ConvertToInt<uint32_t>();
    zero.SetModulus(q);
    NativeInteger temp_b= 5*q/8;
    LWECiphertext ct_temp = std::make_shared<LWECiphertextImpl>(LWECiphertextImpl(std::move(zero), temp_b.Mod(q)));

    // the additive homomorphic operation for XOR/NXOR is different from the other gates we compute
    // 2*(ct1 - ct2) mod 4 for XOR, me map 1,2 -> 1 and 3,0 -> 0
    if ((gate == XOR_FAST) || (gate == XNOR_FAST)) {
        LWEscheme->EvalSubEq(ctprep, ct2);
        LWEscheme->EvalAddEq(ctprep, ctprep);
    }
    else {
        LWEscheme->EvalAddEq(ctprep, ct2);
        LWEscheme->EvalSubEq(ct_temp,ctprep);

    }
      
    auto acc{BootstrapGateCore(params, gate, EK.BSkey, ct_temp)};  //

    NativePoly& accVec{acc->GetElements()};
    accVec = accVec.Transpose();
    accVec.SetFormat(Format::COEFFICIENT);
   
    // we add Q/8 to "b" to to map back to Q/4 (i.e., mod 2) arithmetic.
    const auto& LWEParams = params->GetLWEParams();
    NativeInteger Q{LWEParams->GetQ()};
    NativeInteger b{(Q >> 3) + 1};
    auto ctExt = std::make_shared<LWECiphertextImpl>(std::move(accVec.GetValues()), std::move(b));

    // Modulus switching to a middle step Q'
    auto ctMS = LWEscheme->ModSwitch(LWEParams->GetqKS(), ctExt);
    // Key switching
    auto ctKS = LWEscheme->KeySwitch(LWEParams, EK.KSkey, ctMS);
    // Modulus switching
    return LWEscheme->ModSwitch(ct1->GetModulus(), ctKS);
}

// Full evaluation as described in https://eprint.iacr.org/2020/086
LWECiphertext BinFHEScheme::EvalBinGate(const std::shared_ptr<BinFHECryptoParams>& params, BINGATE gate,
                                        const RingGSWBTKey& EK, ConstLWECiphertext& ct1,
                                        ConstLWECiphertext& ct2) const {
    if (ct1 == ct2)
        OPENFHE_THROW(config_error, "Input ciphertexts should be independant");

    // By default, we compute XOR/XNOR using a combination of AND, OR, and NOT gates 
    if ((gate == XOR) || (gate == XNOR)) {
        const auto& ctAND1 = EvalBinGate(params, AND, EK, ct1, EvalNOT(params, ct2));
        const auto& ctAND2 = EvalBinGate(params, AND, EK, EvalNOT(params, ct1), ct2);
        const auto& ctOR   = EvalBinGate(params, OR, EK, ctAND1, ctAND2);

        // NOT is free so there is not cost to do it an extra time for XNOR
        return (gate == XOR) ? ctOR : EvalNOT(params, ctOR);
    }

    LWECiphertext ctprep = std::make_shared<LWECiphertextImpl>(*ct1);
    // the additive homomorphic operation for XOR/NXOR is different from the other gates we compute
    // 2*(ct1 - ct2) mod 4 for XOR, me map 1,2 -> 1 and 3,0 -> 0
    if ((gate == XOR_FAST) || (gate == XNOR_FAST)) {
        LWEscheme->EvalSubEq(ctprep, ct2);
        LWEscheme->EvalAddEq(ctprep, ctprep);
    }
    else {
        // for all other gates, we simply compute (ct1 + ct2) mod 4
        // for AND: 0,1 -> 0 and 2,3 -> 1
        // for OR: 1,2 -> 1 and 3,0 -> 0
        LWEscheme->EvalAddEq(ctprep, ct2);
    }

    auto acc{BootstrapGateCore(params, gate, EK.BSkey, ctprep)};

    // the accumulator result is encrypted w.r.t. the transposed secret key
    // we can transpose "a" to get an encryption under the original secret key
    std::vector<NativePoly>& accVec{acc->GetElements()};
    accVec[0] = accVec[0].Transpose();  
    accVec[0].SetFormat(Format::COEFFICIENT);
    accVec[1].SetFormat(Format::COEFFICIENT);

    // we add Q/8 to "b" to to map back to Q/4 (i.e., mod 2) arithmetic.
    const auto& LWEParams = params->GetLWEParams();
    NativeInteger Q{LWEParams->GetQ()};
    NativeInteger b{(Q >> 3) + 1};
    b.ModAddFastEq(accVec[1][0], Q);

    auto ctExt = std::make_shared<LWECiphertextImpl>(std::move(accVec[0].GetValues()), std::move(b));
    // Modulus switching to a middle step Q'
    auto ctMS = LWEscheme->ModSwitch(LWEParams->GetqKS(), ctExt);
    // Key switching
    auto ctKS = LWEscheme->KeySwitch(LWEParams, EK.KSkey, ctMS);
    // Modulus switching
    return LWEscheme->ModSwitch(ct1->GetModulus(), ctKS);
}





// Full evaluation as described in https://eprint.iacr.org/2020/086
LWECiphertext BinFHEScheme::EvalBinGate(const std::shared_ptr<BinFHECryptoParams>& params, BINGATE gate,
                                        const RingGSWBTKey& EK, const std::vector<LWECiphertext>& ctvector) const {
    // check if the ciphertexts are all independent
    for (size_t i = 0; i < ctvector.size(); i++) {
        for (size_t j = i + 1; j < ctvector.size(); j++) {
            if (ctvector[j] == ctvector[i]) {
                OPENFHE_THROW(config_error, "Input ciphertexts should be independent");
            }
        }
    }

    NativeInteger p = ctvector[0]->GetptModulus();

    LWECiphertext ctprep = std::make_shared<LWECiphertextImpl>(*ctvector[0]);
    ctprep->SetptModulus(p);
    if ((gate == MAJORITY) || (gate == AND3) || (gate == OR3) || (gate == AND4) || (gate == OR4)) {
        // we simply compute sum(ctvector[i]) mod p
        for (size_t i = 1; i < ctvector.size(); i++) {
            LWEscheme->EvalAddEq(ctprep, ctvector[i]);
        }
        auto acc = BootstrapGateCore(params, gate, EK.BSkey, ctprep);

        std::vector<NativePoly>& accVec = acc->GetElements();
        // the accumulator result is encrypted w.r.t. the transposed secret key
        // we can transpose "a" to get an encryption under the original secret key
        accVec[0] = accVec[0].Transpose();
        accVec[0].SetFormat(Format::COEFFICIENT);
        accVec[1].SetFormat(Format::COEFFICIENT);

        // we add Q/8 to "b" to to map back to Q/4 (i.e., mod 2) arithmetic.
        auto& LWEParams = params->GetLWEParams();
        NativeInteger Q = LWEParams->GetQ();
        NativeInteger b = Q / NativeInteger(2 * p) + 1;
        b.ModAddFastEq(accVec[1][0], Q);

        auto ctExt = std::make_shared<LWECiphertextImpl>(std::move(accVec[0].GetValues()), std::move(b));
        // Modulus switching to a middle step Q'
        auto ctMS = LWEscheme->ModSwitch(LWEParams->GetqKS(), ctExt);
        // Key switching
        auto ctKS = LWEscheme->KeySwitch(LWEParams, EK.KSkey, ctMS);
        // Modulus switching
        return LWEscheme->ModSwitch(ctvector[0]->GetModulus(), ctKS);
    }
    else if (gate == CMUX) {
        if (ctvector.size() != 3)
            OPENFHE_THROW(not_implemented_error, "CMUX gate implemented for ciphertext vectors of size 3");

        auto ccNOT   = EvalNOT(params, ctvector[2]);
        auto ctNAND1 = EvalBinGate(params, NAND, EK, ctvector[0], ccNOT);
        auto ctNAND2 = EvalBinGate(params, NAND, EK, ctvector[1], ctvector[2]);
        auto ctCMUX  = EvalBinGate(params, NAND, EK, ctNAND1, ctNAND2);
        return ctCMUX;
    }
    else {
        OPENFHE_THROW(not_implemented_error, "This gate is not implemented for vector of ciphertexts at this time");
    }
}



// Full evaluation as described in https://eprint.iacr.org/2020/086
LWECiphertext BinFHEScheme::Bootstrap(const std::shared_ptr<BinFHECryptoParams>& params, const RingGSWBTKey& EK,
                                      ConstLWECiphertext& ct) const {
    NativeInteger p = ct->GetptModulus();
    LWECiphertext ctprep{std::make_shared<LWECiphertextImpl>(*ct)};
    // ctprep = ct + q/4
    LWEscheme->EvalAddConstEq(ctprep, (ct->GetModulus() >> 2));

    auto acc{BootstrapGateCore(params, AND, EK.BSkey, ctprep)};

    // the accumulator result is encrypted w.r.t. the transposed secret key
    // we can transpose "a" to get an encryption under the original secret key
    std::vector<NativePoly>& accVec{acc->GetElements()};
    accVec[0] = accVec[0].Transpose();
    accVec[0].SetFormat(Format::COEFFICIENT);
    accVec[1].SetFormat(Format::COEFFICIENT);

    // we add Q/8 to "b" to to map back to Q/4 (i.e., mod 2) arithmetic.
    const auto& LWEParams = params->GetLWEParams();
    NativeInteger Q{LWEParams->GetQ()};
    NativeInteger b = Q / NativeInteger(2 * p) + 1;
    b.ModAddFastEq(accVec[1][0], Q);
 
    auto ctExt = std::make_shared<LWECiphertextImpl>(std::move(accVec[0].GetValues()), std::move(b));
    // Modulus switching to a middle step Q'
    auto ctMS = LWEscheme->ModSwitch(LWEParams->GetqKS(), ctExt);
    // Key switching
    auto ctKS = LWEscheme->KeySwitch(LWEParams, EK.KSkey, ctMS);
    // Modulus switching
    return LWEscheme->ModSwitch(ct->GetModulus(), ctKS);
}

// Evaluation of the NOT operation; no key material is needed
LWECiphertext BinFHEScheme::EvalNOT(const std::shared_ptr<BinFHECryptoParams>& params, ConstLWECiphertext& ct) const {
    NativeInteger q{ct->GetModulus()};
    uint32_t n{ct->GetLength()};

    NativeVector a(n, q);
    for (uint32_t i = 0; i < n; ++i)
        a[i] = ct->GetA(i) == 0 ? 0 : q - ct->GetA(i);

    return std::make_shared<LWECiphertextImpl>(std::move(a), (q >> 2).ModSubFast(ct->GetB(), q));
}

// Evaluate Arbitrary Function homomorphically
// Modulus of ct is q | 2N
LWECiphertext BinFHEScheme::EvalFunc(const std::shared_ptr<BinFHECryptoParams>& params, const RingGSWBTKey& EK,
                                     ConstLWECiphertext& ct, const std::vector<NativeInteger>& LUT,
                                     const NativeInteger& beta) const {
    auto ct1 = std::make_shared<LWECiphertextImpl>(*ct);
    NativeInteger q{ct->GetModulus()};
    uint32_t functionProperty{this->checkInputFunction(LUT, q)};

    if (functionProperty == 0) {  // negacyclic function only needs one bootstrap
        auto fLUT = [LUT](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
            return LUT[x.ConvertToInt()];
        };
        LWEscheme->EvalAddConstEq(ct1, beta);
        return BootstrapFunc(params, EK, ct1, fLUT, q);
    }

    if (functionProperty == 2) {  // arbitary funciton
        const auto& LWEParams = params->GetLWEParams();
        uint32_t N{LWEParams->GetN()};
        if (q.ConvertToInt() > N) {  // need q to be at most = N for arbitary function
            std::string errMsg =
                "ERROR: ciphertext modulus q needs to be <= ring dimension for arbitrary function evaluation";
            OPENFHE_THROW(not_implemented_error, errMsg);
        }

        // TODO: figure out a way to not do this :(

        // repeat the LUT to make it periodic
        std::vector<NativeInteger> LUT2 = LUT;
        LUT2.insert(LUT2.end(), LUT.begin(), LUT.end());

        NativeInteger dq{q << 1};
        // raise the modulus of ct1 : q -> 2q
        ct1->GetA().SetModulus(dq);

        auto ct2 = std::make_shared<LWECiphertextImpl>(*ct1);
        LWEscheme->EvalAddConstEq(ct2, beta);
        // this is 1/4q_small or -1/4q_small mod q
        auto f0 = [](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
            if (x < (q >> 1))
                return Q - (q >> 2);
            else
                return (q >> 2);
        };
        auto ct3 = BootstrapFunc(params, EK, ct2, f0, dq);
        LWEscheme->EvalSubEq2(ct1, ct3);
        LWEscheme->EvalAddConstEq(ct3, beta);
        LWEscheme->EvalSubConstEq(ct3, q >> 1);

        // Now the input is within the range [0, q/2).
        // Note that for non-periodic function, the input q is boosted up to 2q
        auto fLUT2 = [LUT2](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
            if (x < (q >> 1))
                return LUT2[x.ConvertToInt()];
            else
                return Q - LUT2[x.ConvertToInt() - q.ConvertToInt() / 2];
        };
        auto ct4 = BootstrapFunc(params, EK, ct3, fLUT2, dq);
        ct4->SetModulus(q);
        return ct4;
    }

    // Else it's periodic function so we evaluate directly
    LWEscheme->EvalAddConstEq(ct1, beta);
    // this is 1/4q_small or -1/4q_small mod q
    auto f0 = [](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
        if (x < (q >> 1))
            return Q - (q >> 2);
        else
            return (q >> 2);
    };
    auto ct2 = BootstrapFunc(params, EK, ct1, f0, q);
    LWEscheme->EvalSubEq2(ct, ct2);
    LWEscheme->EvalAddConstEq(ct2, beta);
    LWEscheme->EvalSubConstEq(ct2, q >> 2);

    // Now the input is within the range [0, q/2).
    // Note that for non-periodic function, the input q is boosted up to 2q
    auto fLUT1 = [LUT](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
        if (x < (q >> 1))
            return LUT[x.ConvertToInt()];
        else
            return Q - LUT[x.ConvertToInt() - q.ConvertToInt() / 2];
    };
    return BootstrapFunc(params, EK, ct2, fLUT1, q);
}

// Evaluate Homomorphic Flooring
LWECiphertext BinFHEScheme::EvalFloor(const std::shared_ptr<BinFHECryptoParams>& params, const RingGSWBTKey& EK,
                                      ConstLWECiphertext& ct, const NativeInteger& beta, uint32_t roundbits) const {
    const auto& LWEParams = params->GetLWEParams();
    NativeInteger q{roundbits == 0 ? LWEParams->Getq() : beta * (1 << roundbits + 1)};
    NativeInteger mod{ct->GetModulus()};

    auto ct1 = std::make_shared<LWECiphertextImpl>(*ct);
    LWEscheme->EvalAddConstEq(ct1, beta);

    auto ct1Modq = std::make_shared<LWECiphertextImpl>(*ct1);
    ct1Modq->SetModulus(q);
    // this is 1/4q_small or -1/4q_small mod q
    auto f1 = [](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
        if (x < (q >> 1))
            return Q - (q >> 2);
        else
            return (q >> 2);
    };
    auto ct2 = BootstrapFunc(params, EK, ct1Modq, f1, mod);
    LWEscheme->EvalSubEq(ct1, ct2);

    auto ct2Modq = std::make_shared<LWECiphertextImpl>(*ct1);
    ct2Modq->SetModulus(q);

    // now the input is only within the range [0, q/2)
    auto f2 = [](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
        if (x < (q >> 2))
            return Q - (q >> 1) - x;
        else if (((q >> 2) <= x) && (x < 3 * (q >> 2)))
            return x;
        else
            return Q + (q >> 1) - x;
    };
    auto ct3 = BootstrapFunc(params, EK, ct2Modq, f2, mod);
    LWEscheme->EvalSubEq(ct1, ct3);

    return ct1;
}

// Evaluate large-precision sign
LWECiphertext BinFHEScheme::EvalSign(const std::shared_ptr<BinFHECryptoParams>& params,
                                     const std::map<uint32_t, RingGSWBTKey>& EKs, ConstLWECiphertext& ct,
                                     const NativeInteger& beta, bool schemeSwitch) const {
    auto mod{ct->GetModulus()};
    const auto& LWEParams = params->GetLWEParams();
    auto q{LWEParams->Getq()};
    if (mod <= q) {
        std::string errMsg =
            "ERROR: EvalSign is only for large precision. For small precision, please use bootstrapping directly";
        OPENFHE_THROW(not_implemented_error, errMsg);
    }

    const auto& RGSWParams = params->GetRingGSWParams();
    const auto curBase     = RGSWParams->GetBaseG();
    auto search            = EKs.find(curBase);
    if (search == EKs.end()) {
        std::string errMsg("ERROR: No key [" + std::to_string(curBase) + "] found in the map");
        OPENFHE_THROW(openfhe_error, errMsg);
    }
    RingGSWBTKey curEK(search->second);

    auto cttmp = std::make_shared<LWECiphertextImpl>(*ct);
    while (mod > q) {
        cttmp = EvalFloor(params, curEK, cttmp, beta);
        // round Q to 2betaQ/q
        //  mod   = mod / q * 2 * beta;
        mod   = (mod << 1) * beta / q;
        cttmp = LWEscheme->ModSwitch(mod, cttmp);

        // if dynamic
        if (EKs.size() == 3) {
            // TODO: use GetMSB()?
            uint32_t binLog = static_cast<uint32_t>(ceil(GetMSB(mod.ConvertToInt()) - 1));
            uint32_t base{0};
            if (binLog <= static_cast<uint32_t>(17))
                base = static_cast<uint32_t>(1) << 27;
            else if (binLog <= static_cast<uint32_t>(26))
                base = static_cast<uint32_t>(1) << 18;

            if (0 != base) {  // if base is to change ...
                RGSWParams->Change_BaseG(base);

                auto search = EKs.find(base);
                if (search == EKs.end()) {
                    std::string errMsg("ERROR: No key [" + std::to_string(curBase) + "] found in the map");
                    OPENFHE_THROW(openfhe_error, errMsg);
                }
                curEK = search->second;
            }
        }
    }
    LWEscheme->EvalAddConstEq(cttmp, beta);

    if (!schemeSwitch) {
        // if the ended q is smaller than q, we need to change the param for the final boostrapping
        auto f3 = [](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
            return (x < q / 2) ? (Q / 4) : (Q - Q / 4);
        };
        cttmp = BootstrapFunc(params, curEK, cttmp, f3, q);  // this is 1/4q_small or -1/4q_small mod q
        LWEscheme->EvalSubConstEq(cttmp, q >> 2);
    }
    else {  // return the negated f3 and do not subtract q/4 for a more natural encoding in scheme switching
        // if the ended q is smaller than q, we need to change the param for the final boostrapping
        auto f3 = [](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
            return (x < q / 2) ? (Q - Q / 4) : (Q / 4);
        };
        cttmp = BootstrapFunc(params, curEK, cttmp, f3, q);  // this is 1/4q_small or -1/4q_small mod q
    }
    RGSWParams->Change_BaseG(curBase);
    return cttmp;
}

// Evaluate Ciphertext Decomposition
std::vector<LWECiphertext> BinFHEScheme::EvalDecomp(const std::shared_ptr<BinFHECryptoParams>& params,
                                                    const std::map<uint32_t, RingGSWBTKey>& EKs, ConstLWECiphertext& ct,
                                                    const NativeInteger& beta) const {
    auto mod         = ct->GetModulus();
    auto& LWEParams  = params->GetLWEParams();
    auto& RGSWParams = params->GetRingGSWParams();

    NativeInteger q = LWEParams->Getq();
    if (mod <= q) {
        std::string errMsg =
            "ERROR: EvalDecomp is only for large precision. For small precision, please use bootstrapping directly";
        OPENFHE_THROW(not_implemented_error, errMsg);
    }

    const auto curBase = RGSWParams->GetBaseG();
    auto search        = EKs.find(curBase);
    if (search == EKs.end()) {
        std::string errMsg("ERROR: No key [" + std::to_string(curBase) + "] found in the map");
        OPENFHE_THROW(openfhe_error, errMsg);
    }
    RingGSWBTKey curEK(search->second);

    auto cttmp = std::make_shared<LWECiphertextImpl>(*ct);
    std::vector<LWECiphertext> ret;
    while (mod > q) {
        auto ctq = std::make_shared<LWECiphertextImpl>(*cttmp);
        ctq->SetModulus(q);
        ret.push_back(std::move(ctq));

        // Floor the input sequentially to obtain the most significant bit
        cttmp = EvalFloor(params, curEK, cttmp, beta);
        mod   = mod / q * 2 * beta;
        // round Q to 2betaQ/q
        cttmp = LWEscheme->ModSwitch(mod, cttmp);

        if (EKs.size() == 3) {  // if dynamic
            uint32_t binLog = static_cast<uint32_t>(ceil(log2(mod.ConvertToInt())));
            uint32_t base   = 0;
            if (binLog <= static_cast<uint32_t>(17))
                base = static_cast<uint32_t>(1) << 27;
            else if (binLog <= static_cast<uint32_t>(26))
                base = static_cast<uint32_t>(1) << 18;

            if (0 != base) {  // if base is to change ...
                RGSWParams->Change_BaseG(base);

                auto search = EKs.find(base);
                if (search == EKs.end()) {
                    std::string errMsg("ERROR: No key [" + std::to_string(curBase) + "] found in the map");
                    OPENFHE_THROW(openfhe_error, errMsg);
                }
                curEK = search->second;
            }
        }
    }
    RGSWParams->Change_BaseG(curBase);
    ret.push_back(std::move(cttmp));
    return ret;
}

// private:
//mklwe
MKACCCiphertext BinFHEScheme::BootstrapGateCore(const std::shared_ptr<BinFHECryptoParams>& params, BINGATE gate,
                                     ConstUniEncACCKey& ek,std::vector<std::vector<NativePoly>> Pkey,std::vector<NativePoly> skf,ConstMKLWECiphertext& ct) const{
    // std::cout<<"In BinFHEScheme BootstrapGateCore"<<std::endl; 
    if (ek == nullptr) {
        std::string errMsg =
            "Bootstrapping keys have not been generated. Please call MKBTKeyGen "
            "before calling bootstrapping.";
        OPENFHE_THROW(config_error, errMsg);
    } 
    auto& UniEncParams = params->GetUniEncParams();
    auto polyParams  = UniEncParams->GetPolyParams();
    NativeInteger p  = ct->GetptModulus();    //
    NativeInteger q  = ct->GetModulus();                                       //1024
    NativeInteger Q      = UniEncParams->GetQ();             //
    NativeInteger Q2p    = Q / NativeInteger(2 * p) + 1;  //Q/8+1
    NativeInteger Q2pNeg = Q - Q2p;                       //7/8Q-1
    uint32_t N = UniEncParams->GetN();
    auto k = UniEncParams->Getk();
    NativeVector Rx(N, Q);
    // std::cout<<"Q2p = "<<Q2p<<std::endl;        
    for (uint32_t j = 0; j < N; ++j) {
        Rx[j] = j<N/2 ? Q2p :Q2pNeg;
    }
   //  cout<<"Rx = "<<Rx<<endl;
    const NativeInteger& b = ct->GetB();
    auto b_hat = b*2*N/q;
   //  cout<<"b-Hat = "<<b_hat<<endl;
    
    NativeVector Rxxb(N, Q);
    for (uint32_t j = 0; j < N; ++j) {
        auto index = b_hat.ConvertToInt()+j;
        if (index>=N && index<2*N )
        {
            Rxxb[index%N] =Q- Rx[j];
        }
        else//index<N
        {
            Rxxb[index%N] = Rx[j];
        }
    }
    // cout<<"Rxxb = "<<Rxxb<<endl;

    
    std::vector<NativePoly> res(k);
    for(uint32_t u=1;u<k;u++)
    {
        res[u] = NativePoly(polyParams, Format::EVALUATION, true);
    }
    
    res[0] = NativePoly(polyParams, Format::COEFFICIENT, false);
    res[0].SetValues(std::move(Rxxb), Format::COEFFICIENT);
    res[0].SetFormat(Format::EVALUATION);

    MKACCCiphertext acc = std::make_shared<MKACCCiphertextImpl>(std::move(res));


    std::vector<NativeVector> Aneg = ct->GetAneg();
    // for(uint32_t u=0;u<k;u++){
    //     cout<<"A[u] = "<<ct->GetA()[u]<<endl;
    //     cout<<"Aneg[u] = "<<Aneg[u]<<endl;
    // }
    UniEncACCscheme->EvalAcc(UniEncParams,ek,Pkey,skf,acc,Aneg);
    return acc;
}




MKACCCiphertext BinFHEScheme::BootstrapGateCore(const std::shared_ptr<BinFHECryptoParams>& params, BINGATE gate,
                                     ConstUniEncACCKey& ek,std::vector<std::vector<NativePoly>> Pkey,std::vector<NativePoly> skf,ConstMNTRUCiphertext& ct) const{
    // std::cout<<"In BinFHEScheme BootstrapGateCore"<<std::endl;                
    if (ek == nullptr) {
        std::string errMsg =
            "Bootstrapping keys have not been generated. Please call MKBTKeyGen "
            "before calling bootstrapping.";
        OPENFHE_THROW(config_error, errMsg);
    }
    // auto& MNTRUParams  = params->GetMatrixNTRUParams();
    auto& UniEncParams = params->GetUniEncParams();
    auto polyParams  = UniEncParams->GetPolyParams();

    NativeInteger p  = ct->GetptModulus();    //
    //NativeInteger q  = ct->GetModulus();                                       //1024
    NativeInteger Q      = UniEncParams->GetQ();             //
    NativeInteger Q2p    = Q / NativeInteger(2 * p) + 1;  //Q/8+1
    NativeInteger Q2pNeg = Q - Q2p;                       //7/8Q-1
    uint32_t N = UniEncParams->GetN();
    auto k = UniEncParams->Getk();
    NativeVector Rx(N, Q);
    // std::cout<<"Q2p = "<<Q2p<<std::endl;        

    for (size_t j = 0; j < N; ++j) {
        Rx[j] = j<N/2 ?  Q2pNeg:Q2p;
    }
    // NativePoly polyRx(polyParams);
    // polyRx.SetValues(Rx, Format::COEFFICIENT);
    // polyRx.SetFormat(EVALUATION);

    // NativeVector Zero(N, Q);
    // std::cout<<"Zero = "<<Zero<<std::endl;        
    // NativePoly polyZero(polyParams);
    // polyRx.SetValues(Zero, Format::COEFFICIENT);
    // polyRx.SetFormat(EVALUATION);

    std::vector<NativePoly> res(k);
    for(uint32_t u=1;u<k;u++)
    {
        res[u] = NativePoly(polyParams, Format::EVALUATION, true);
    }
    
    res[0] = NativePoly(polyParams, Format::COEFFICIENT, false);
    res[0].SetValues(std::move(Rx), Format::COEFFICIENT);
    res[0].SetFormat(Format::EVALUATION);

   // std::cout<<"ACC 0  = "<<res[0]<<std::endl; 
    //std::cout<<"GetFormat = "<<res[0].GetFormat()<<std::endl; 
     //std::cout<<"ACC 1 = "<<res[1]<<std::endl; 
    // std::cout<<"GetFormat = "<<res[1].GetFormat()<<std::endl; 


    MKACCCiphertext acc = std::make_shared<MKACCCiphertextImpl>(std::move(res));

    // std::cout<<"调用EvalACC"<<std::endl;        
    UniEncACCscheme->EvalAcc(UniEncParams,ek,Pkey,skf,acc,ct->GetElements());

    return acc;
}





NTRUCiphertext BinFHEScheme::BootstrapGateCore(const std::shared_ptr<BinFHECryptoParams>& params, BINGATE gate,
                                               ConstVectorNTRUACCKey& ek, ConstLWECiphertext& ct) const {
    if (ek == nullptr) {
        std::string errMsg =
            "Bootstrapping keys have not been generated. Please call BTKeyGen "
            "before calling bootstrapping.";
        OPENFHE_THROW(config_error, errMsg);
    }

    auto& LWEParams  = params->GetLWEParams();
    auto& NTRUParams = params->GetVectorNTRUParams();
    auto polyParams  = NTRUParams->GetPolyParams();

    // Specifies the range [q1,q2) that will be used for mapping
    NativeInteger p  = ct->GetptModulus();                                     
    NativeInteger q  = ct->GetModulus();                                       //1024
    NativeInteger Q      = LWEParams->GetQ();             //
    NativeInteger Q2p    = Q / NativeInteger(2 * p) + 1;  //Q/8+1
    NativeInteger Q2pNeg = Q - Q2p;                       //7/8Q-1

    uint32_t N = LWEParams->GetN();
                   
    NativeVector m(N, Q);
    NativeVector new_m(N, Q);
    // Since q | (2*N), we deal with a sparse embedding of Z_Q[x]/(X^{q/2}+1) to
    // Z_Q[x]/(X^N+1)
    uint32_t factor = (2 * N / q.ConvertToInt());
    const NativeInteger& b = ct->GetB()*(2*NativeInteger(N)/q);// 0~2N

    for (size_t j = 0; j < N; ++j) {
        m[j] = j<N/2 ?  Q2p:Q2pNeg;
    }
    for (size_t j = 0; j < N; ++j) {
        auto k = b.ConvertToInt()+j;
        if (k>=N && k<2*N )
        {
            new_m[k%N]=Q- m[j];
        }
        else
        {
             new_m[k%N]= m[j];
        }
    }
    NativeInteger azero = ct->GetA()[0];
    uint32_t wzero = factor * azero.ConvertToInt() + 1;
    uint32_t invw = ModInverse(wzero, 2 * N) % (2 * N);
    NativePoly polym(polyParams);
    polym.SetValues(new_m, Format::COEFFICIENT);
    polym.SetFormat(EVALUATION);
    auto polym2{polym.AutomorphismTransform(invw)};  
    auto acc = std::make_shared<NTRUCiphertextImpl>(std::move(polym2));
    NACCscheme->EvalAcc(NTRUParams, ek, acc, ct->GetA());
    return acc;
}

RLWECiphertext BinFHEScheme::BootstrapGateCore(const std::shared_ptr<BinFHECryptoParams>& params, BINGATE gate,
                                               ConstRingGSWACCKey& ek, ConstLWECiphertext& ct) const {
    if (ek == nullptr) {
        std::string errMsg =
            "Bootstrapping keys have not been generated. Please call BTKeyGen "
            "before calling bootstrapping.";
        OPENFHE_THROW(config_error, errMsg);
    }

    auto& LWEParams  = params->GetLWEParams();
    auto& RGSWParams = params->GetRingGSWParams();
    auto polyParams  = RGSWParams->GetPolyParams();

    // Specifies the range [q1,q2) that will be used for mapping
    NativeInteger p  = ct->GetptModulus();  //4 
    NativeInteger q  = ct->GetModulus();
    uint32_t qHalf   = q.ConvertToInt() >> 1;
    NativeInteger q1 = RGSWParams->GetGateConst()[static_cast<size_t>(gate)];  //3/8q
    NativeInteger q2 = q1.ModAddFast(NativeInteger(qHalf), q);                 //7/8

    // depending on whether the value is the range, it will be set
    // to either Q/8 or -Q/8 to match binary arithmetic
    NativeInteger Q      = LWEParams->GetQ();
    NativeInteger Q2p    = Q / NativeInteger(2 * p) + 1;  //Q/8+1
    NativeInteger Q2pNeg = Q - Q2p;                       //7/8Q-1

    uint32_t N = LWEParams->GetN();
    NativeVector m(N, Q);
    // Since q | (2*N), we deal with a sparse embedding of Z_Q[x]/(X^{q/2}+1) to
    // Z_Q[x]/(X^N+1)
    uint32_t factor = (2 * N / q.ConvertToInt());

    const NativeInteger& b = ct->GetB();
    for (size_t j = 0; j < qHalf; ++j) {
        NativeInteger temp = b.ModSub(j, q);
        if (q1 < q2)
            m[j * factor] = ((temp >= q1) && (temp < q2)) ? Q2pNeg : Q2p;
        else
            m[j * factor] = ((temp >= q2) && (temp < q1)) ? Q2p : Q2pNeg;
    }
    //m(x)-m(x^w)
    std::vector<NativePoly> res(2);
    // no need to do NTT as all coefficients of this poly are zero
    res[0] = NativePoly(polyParams, Format::EVALUATION, true);
    res[1] = NativePoly(polyParams, Format::COEFFICIENT, false);
    res[1].SetValues(std::move(m), Format::COEFFICIENT);
    res[1].SetFormat(Format::EVALUATION);

    // main accumulation computation
    // the following loop is the bottleneck of bootstrapping/binary gate
    // evaluation
 
    auto acc = std::make_shared<RLWECiphertextImpl>(std::move(res));
    ACCscheme->EvalAcc(RGSWParams, ek, acc, ct->GetA());
    return acc;
}

// Functions below are for large-precision sign evaluation, 
// flooring, homomorphic digit decomposition, and arbitrary 
// funciton evaluation, from https://eprint.iacr.org/2021/1337
template <typename Func>
RLWECiphertext BinFHEScheme::BootstrapFuncCore(const std::shared_ptr<BinFHECryptoParams>& params,
                                               ConstRingGSWACCKey& ek, ConstLWECiphertext& ct, const Func f,
                                               const NativeInteger& fmod) const {
    if (ek == nullptr) {
        std::string errMsg =
            "Bootstrapping keys have not been generated. Please call BTKeyGen before calling bootstrapping.";
        OPENFHE_THROW(config_error, errMsg);
    }

    auto& LWEParams  = params->GetLWEParams();
    auto& RGSWParams = params->GetRingGSWParams();
    auto polyParams  = RGSWParams->GetPolyParams();

    NativeInteger Q = LWEParams->GetQ();
    uint32_t N      = LWEParams->GetN();
    NativeVector m(N, Q);
    // For specific function evaluation instead of general bootstrapping
    NativeInteger ctMod    = ct->GetModulus();
    uint32_t factor        = (2 * N / ctMod.ConvertToInt());
    const NativeInteger& b = ct->GetB();
    for (size_t j = 0; j < (ctMod >> 1); ++j) {
        NativeInteger temp = b.ModSub(j, ctMod);
        m[j * factor]      = Q.ConvertToInt() / fmod.ConvertToInt() * f(temp, ctMod, fmod);
    }
    std::vector<NativePoly> res(2);
    // no need to do NTT as all coefficients of this poly are zero
    res[0] = NativePoly(polyParams, Format::EVALUATION, true);
    res[1] = NativePoly(polyParams, Format::COEFFICIENT, false);
    res[1].SetValues(std::move(m), Format::COEFFICIENT);
    res[1].SetFormat(Format::EVALUATION);

    // main accumulation computation
    // the following loop is the bottleneck of bootstrapping/binary gate
    // evaluation
    auto acc = std::make_shared<RLWECiphertextImpl>(std::move(res));
    ACCscheme->EvalAcc(RGSWParams, ek, acc, ct->GetA());
    return acc;
}

// Full evaluation as described in https://eprint.iacr.org/2020/086
template <typename Func>
LWECiphertext BinFHEScheme::BootstrapFunc(const std::shared_ptr<BinFHECryptoParams>& params, const RingGSWBTKey& EK,
                                          ConstLWECiphertext& ct, const Func f, const NativeInteger& fmod) const {
    auto acc = BootstrapFuncCore(params, EK.BSkey, ct, f, fmod);

    std::vector<NativePoly>& accVec = acc->GetElements();
    // the accumulator result is encrypted w.r.t. the transposed secret key
    // we can transpose "a" to get an encryption under the original secret key
    accVec[0] = accVec[0].Transpose();
    accVec[0].SetFormat(Format::COEFFICIENT);
    accVec[1].SetFormat(Format::COEFFICIENT);

    auto ctExt      = std::make_shared<LWECiphertextImpl>(std::move(accVec[0].GetValues()), std::move(accVec[1][0]));
    auto& LWEParams = params->GetLWEParams();
    // Modulus switching to a middle step Q'
    auto ctMS = LWEscheme->ModSwitch(LWEParams->GetqKS(), ctExt);
    // Key switching
    auto ctKS = LWEscheme->KeySwitch(LWEParams, EK.KSkey, ctMS);
    // Modulus switching
    return LWEscheme->ModSwitch(fmod, ctKS);
}
}
;  // namespace lbcrypto
