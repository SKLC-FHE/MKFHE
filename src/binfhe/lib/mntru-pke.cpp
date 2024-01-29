
#include "mntru-pke.h"

#include "math/binaryuniformgenerator.h"
#include "math/discreteuniformgenerator.h"
#include "math/ternaryuniformgenerator.h"
// #define WITH_NOISE_DEBUG

namespace lbcrypto {
// the main rounding operation used in ModSwitch (as described in Section 3 of
// https://eprint.iacr.org/2014/816) The idea is that Round(x) = 0.5 + Floor(x)
NativeInteger MNTRUEncryptionScheme::RoundqQ(const NativeInteger& v, const NativeInteger& q,
                                             const NativeInteger& Q) const {
    return NativeInteger(static_cast<BasicInteger>(
                             std::floor(0.5 + v.ConvertToDouble() * q.ConvertToDouble() / Q.ConvertToDouble())))
        .Mod(q);
}

void MNTRUEncryptionScheme::Get_invertible_Matrix(std::vector<NativeVector>& NatMat,
                                                  std::vector<NativeVector>& NatMat_inv, uint32_t q_base, uint32_t N,
                                                  SecretKeyDist keyDist) const {
    // 三值集合的均匀分布
    uniform_int_distribution<int> ternary_sampler(-1, 1);
    //正态分布
    normal_distribution<double> gaussian_sampler(0.0, 1);
    // 随机引擎
    default_random_engine rand_engine(std::chrono::system_clock::now().time_since_epoch().count());

    std::vector<std::vector<int>> mat     = std::vector<std::vector<int>>(N, std::vector<int>(N, 0));
    std::vector<std::vector<int>> mat_inv = std::vector<std::vector<int>>(N, std::vector<int>(N, 0));

    uint32_t half_q_base = q_base / 2;

    //number of rows of the input matrix
    int dim = mat.size();

    //element of Z_(q_base)
    ZZ_p coef;
    coef.init(ZZ(q_base));

    //candidate matrix
    mat_ZZ_p tmp_mat(INIT_SIZE, dim, dim);

    //candidate inverse matrix
    mat_ZZ_p tmp_mat_inv(INIT_SIZE, dim, dim);

    //sampling and testing
    while (true) {
        //sampling
        for (int i = 0; i < dim; i++) {
            Vec<ZZ_p>& row = tmp_mat[i];
            for (int j = 0; j < dim; j++) {
                if (keyDist == UNIFORM_TERNARY) {
                    coef = ternary_sampler(rand_engine);
                }
                else {
                    coef = gaussian_sampler(rand_engine);
                }
                row[j] = coef;
            }
        }
        //test invertibility
        try {
            inv(tmp_mat_inv, tmp_mat);
            break;
        }
        catch (...) {
            //cout << "Matrix " << tmp_mat << " is singular" << endl;
            continue;
        }
    }
    //lift mod q representation to integers
    uint32_t tmp_coef;
    for (int i = 0; i < dim; i++) {
        Vec<ZZ_p>& tmp_row     = tmp_mat[i];
        Vec<ZZ_p>& tmp_row_inv = tmp_mat_inv[i];
        vector<int>& row       = mat[i];
        vector<int>& row_inv   = mat_inv[i];
        for (int j = 0; j < dim; j++) {
            tmp_coef = conv<long>(tmp_row[j]);
            if (tmp_coef > half_q_base)
                tmp_coef -= q_base;
            row[j] = tmp_coef;

            tmp_coef = conv<long>(tmp_row_inv[j]);
            if (tmp_coef > half_q_base)
                tmp_coef -= q_base;
            row_inv[j] = tmp_coef;
        }
    }
    // vector<int> to NativeVector
    for (uint32_t i = 0; i < N; i++) {
        for (uint32_t j = 0; j < N; j++) {
            int32_t v     = mat[i][j];
            int32_t v_inv = mat_inv[i][j];
            if (v < 0)
                NatMat[i][j] = q_base - typename NativeVector::Integer(-v);
            else
                NatMat[i][j] = typename NativeVector::Integer(v);
            if (v_inv < 0)
                NatMat_inv[i][j] = q_base - typename NativeVector::Integer(-v_inv);
            else
                NatMat_inv[i][j] = typename NativeVector::Integer(v_inv);
        }
    }
}

void MNTRUEncryptionScheme::Get_MatrixA(std::vector<NativeVector>& MatrixA, NativeVector s) const {
    uint32_t n        = s.GetLength();
    NativeInteger mod = s.GetModulus();
    MatrixA.clear();
    MatrixA.resize(n, NativeVector(n, mod));
    for (uint32_t i = 0; i < n; i++) {
        for (uint32_t j = 0; j < i; j++) {
            MatrixA[i][j].ModSubEq(s[n - i + j], mod);
            // std::cout<<"MatrixA= "<<MatrixA[i][j]<<std::endl;
        }
        for (uint32_t j = i; j < n; j++) {
            MatrixA[i][j] = s[j - i];
        }
    }
}

MNTRUPrivateKey MNTRUEncryptionScheme::KeyGen(uint32_t k, usint size, const NativeInteger& modulus) const {
    // TernaryUniformGeneratorImpl<NativeVector> tug;
    vector<NativeVector> NatMat(size, NativeVector(size, modulus));
    vector<NativeVector> NatMat_inv(size, NativeVector(size, modulus));
    uint32_t Q = modulus.ConvertToInt<uint32_t>();

    vector<vector<NativeVector>> F;
    vector<vector<NativeVector>> F_inv;
    for (uint32_t i = 0; i < k; i++) {
        Get_invertible_Matrix(NatMat, NatMat_inv, Q, size, UNIFORM_TERNARY);
        F.push_back(NatMat);
        F_inv.push_back(NatMat_inv);
    }

    return std::make_shared<MNTRUPrivateKeyImpl>(MNTRUPrivateKeyImpl(F, F_inv));
}

MNTRUPrivateKey MNTRUEncryptionScheme::KeyGenGaussian(uint32_t k, usint size, const NativeInteger& modulus) const {
    // TernaryUniformGeneratorImpl<NativeVector> tug;
    vector<NativeVector> NatMat(size, NativeVector(size, modulus));
    vector<NativeVector> NatMat_inv(size, NativeVector(size, modulus));
    uint32_t Q = modulus.ConvertToInt<uint32_t>();

    vector<vector<NativeVector>> F;
    vector<vector<NativeVector>> F_inv;
    for (uint32_t i = 0; i < k; i++) {
        Get_invertible_Matrix(NatMat, NatMat_inv, Q, size, GAUSSIAN);
        F.push_back(NatMat);
        F_inv.push_back(NatMat_inv);
    }

    return std::make_shared<MNTRUPrivateKeyImpl>(MNTRUPrivateKeyImpl(F, F_inv));
}

MNTRUCiphertext MNTRUEncryptionScheme::Encrypt(const std::shared_ptr<MNTRUCryptoParams>& params,
                                               ConstMNTRUPrivateKey& sk, MNTRUPlaintext m, MNTRUPlaintextModulus p,
                                               NativeInteger mod) const {
    if (mod % p != 0 && mod.ConvertToInt() & (1 == 0)) {
        std::string errMsg = "ERROR: ciphertext modulus q needs to be divisible by plaintext modulus p.";
        OPENFHE_THROW(not_implemented_error, errMsg);
    }
    // c = (e + q/4 m) F_inv
    // std::vector<std::vector<NativeVector>> F_inv = sk->GetF_inv(); //模为q_ks
    // std::vector<NativeVector> F_inv_col0 = sk->GetF_inv_col0();

    uint32_t n = sk->GetLength();
    uint32_t k = sk->Getk();
    // std::vector<NativeVector> F0_inv(k,NativeVector(n,0));
    // for(uint32_t i=0;i<k;i++)
    // {
    //     F0_inv[i] = F_inv[i][0];
    //     F0_inv[i].SwitchModulus(mod);
    // }
    std::vector<NativeVector> c(k, NativeVector(n, mod));

    for (uint32_t i = 0; i < k; i++) {
        NativeVector e = params->GetDgg().GenerateVector(n, mod);
        if (i == 0) {
            e[0].ModAddFastEq((m % p) * (mod / p), mod);  //e + q/4 m
            //std::cout << "e[0]+q/4 m = " << e[0] << std::endl;
        }
        //std::cout << "e = " << e << std::endl;

        // F_inv_coli[i].SwitchModulus(mod);//从q_ks切换到q

        for (uint32_t j = 0; j < n; j++) {
            NativeVector F_inv = sk->GetF_inv_coli(j)[i];
            F_inv.SwitchModulus(mod);
            //NativeVector乘法
            NativeVector temp = e.ModMul(F_inv);  //行向量e乘以F的每一列
            //std::cout << temp << std::endl;
            NativeInteger sum(0);
            for (uint32_t l = 0; l < n; l++) {
                sum.ModAddEq(temp[l], mod);
            }
            c[i][j] = sum;
        }
    }
    auto ct = std::make_shared<MNTRUCiphertextImpl>(MNTRUCiphertextImpl(std::move(c)));
    ct->SetptModulus(p);
    return ct;
}

//普通mntru密文解密
void MNTRUEncryptionScheme::Decrypt2(const std::shared_ptr<MNTRUCryptoParams>& params, ConstMNTRUPrivateKey& sk,
                                     ConstMNTRUCiphertext& ct, MNTRUPlaintext* result, MNTRUPlaintextModulus p) const {
    //std::cout<<"In MNTRUEncryptionScheme Decrypt"<<std::endl;
    // Create local variables to speed up the computations
    const NativeInteger& mod = ct->GetModulus();
    //cout<<"mod="<<mod<<endl;
    if (mod % (p * 2) != 0 && mod.ConvertToInt() & (1 == 0)) {
        std::string errMsg = "ERROR: ciphertext modulus q needs to be divisible by plaintext modulus p*2.";
        OPENFHE_THROW(not_implemented_error, errMsg);
    }
    std::vector<NativeVector> c = ct->GetElements();
    // std::vector<std::vector<NativeVector>> F = sk->GetF(); //模为q_ks
    std::vector<NativeVector> F_col0 = sk->GetF_col0();  //模为q_ks

    uint32_t n = sk->GetLength();
    uint32_t k = sk->Getk();
    NativeInteger inner(0);
    for (uint32_t i = 0; i < k; i++) {
        //std::cout<<"Point 222"<<std::endl;
        F_col0[i].SwitchModulus(mod);  //从q_ks切换到q
        //std::cout<<"Point 333"<<std::endl;
        NativeVector temp = c[i].ModMul(F_col0[i]);  //行向量e乘以F的每一列
        NativeInteger sum(0);
        for (uint32_t l = 0; l < n; l++) {
            //std::cout<<"Point 444"<<std::endl;
            sum.ModAddEq(temp[l], mod);  //sum = sum + temp[l]
        }
        inner.ModAddEq(sum, mod);
    }

    //std::cout<<"q/8 = "<<(mod / (p * 2))<<std::endl;  //128
    inner.ModAddFastEq((mod / (p * 2)), mod);

    *result = ((NativeInteger(p) * inner) / mod).ConvertToInt();

#if defined(WITH_NOISE_DEBUG)
    //Noise
    int q              = ct->GetModulus().ConvertToInt();
    NativeInteger temp = inner.ModSubFastEq((mod / (p * 2)), mod);
    ;  //cF
    NativeInteger ans(*result);
    // cout<<"ans="<<ans<<endl;
    temp.ModSubFastEq(NativeVector::Integer(ans * mod / 4), mod);  // cF - q/4 * m  =  e
    int err = temp.ConvertToInt();
    if (err > (q / 4)) {
        err = err - q;
    }
    std::cerr << err << std::endl;
#endif
}

void MNTRUEncryptionScheme::DecryptNAND(const std::shared_ptr<MNTRUCryptoParams>& params, ConstMNTRUPrivateKey& sk,
                                        ConstMNTRUCiphertext& ct, MNTRUPlaintext* result,
                                        MNTRUPlaintextModulus p) const {
    //std::cout<<"In MNTRUEncryptionScheme Decrypt"<<std::endl;
    // Create local variables to speed up the computations
    const NativeInteger& mod = ct->GetModulus();
    //cout<<"mod="<<mod<<endl;
    if (mod % (p / 2 * 2) != 0 && mod.ConvertToInt() & (1 == 0)) {
        std::string errMsg = "ERROR: ciphertext modulus q needs to be divisible by plaintext modulus p*2.";
        OPENFHE_THROW(not_implemented_error, errMsg);
    }
    std::vector<NativeVector> c = ct->GetElements();
    // std::vector<std::vector<NativeVector>> F = sk->GetF(); //模为q_ks
    std::vector<NativeVector> F_col0 = sk->GetF_col0();  //模为q_ks
    uint32_t n                       = sk->GetLength();
    uint32_t k                       = sk->Getk();
    NativeInteger inner(0);
    for (uint32_t i = 0; i < k; i++) {
        //std::cout<<"Point 222"<<std::endl;
        F_col0[i].SwitchModulus(mod);  //从q_ks切换到q
        //std::cout<<"Point 333"<<std::endl;
        NativeVector temp = c[i].ModMul(F_col0[i]);  //行向量e乘以F的每一列
        NativeInteger sum(0);
        for (uint32_t l = 0; l < n; l++) {
            //std::cout<<"Point 444"<<std::endl;
            sum.ModAddEq(temp[l], mod);  //sum = sum + temp[l]
        }
        inner.ModAddEq(sum, mod);
    }

    //std::cout<<"q/4 = "<<(mod / (p * 2))<<std::endl;  //128
    inner.ModAddFastEq((mod / (p / 2 * 2)), mod);

    *result = ((NativeInteger(p / 2) * inner) / mod).ConvertToInt();

#if defined(WITH_NOISE_DEBUG)
    //Noise
    int q              = ct->GetModulus().ConvertToInt();
    NativeInteger temp = inner.ModSubFastEq((mod / (p * 2)), mod);
    ;  //cF
    NativeInteger ans(*result);
    // cout<<"ans="<<ans<<endl;
    temp.ModSubFastEq(NativeVector::Integer(ans * mod / 2), mod);  // cF - q/2 * m  =  e
    int err = temp.ConvertToInt();
    if (err > (q / 4)) {
        err = err - q;
    }
    std::cerr << err << std::endl;
#endif
}

void MNTRUEncryptionScheme::Decrypt(const std::shared_ptr<MNTRUCryptoParams>& params, ConstMNTRUPrivateKey& sk,
                                    ConstMNTRUCiphertext& ct, MNTRUPlaintext* result, MNTRUPlaintextModulus p) const {
    //std::cout<<"In MNTRUEncryptionScheme Decrypt"<<std::endl;
    // Create local variables to speed up the computations
    const NativeInteger& mod = ct->GetModulus();
    //cout<<"mod="<<mod<<endl;
    if (mod % (p * 2) != 0 && mod.ConvertToInt() & (1 == 0)) {
        std::string errMsg = "ERROR: ciphertext modulus q needs to be divisible by plaintext modulus p*2.";
        OPENFHE_THROW(not_implemented_error, errMsg);
    }
    std::vector<NativeVector> c = ct->GetElements();
    // std::vector<std::vector<NativeVector>> F = sk->GetF(); //模为q_ks
    std::vector<NativeVector> F_col0 = sk->GetF_col0();  //模为q_ks

    uint32_t n = sk->GetLength();
    uint32_t k = sk->Getk();
    NativeInteger inner(0);
    for (uint32_t i = 0; i < k; i++) {
        //std::cout<<"Point 222"<<std::endl;
        F_col0[i].SwitchModulus(mod);  //从q_ks切换到q
        //std::cout<<"Point 333"<<std::endl;
        NativeVector temp = c[i].ModMul(F_col0[i]);  //行向量乘以F
        NativeInteger sum(0);
        for (uint32_t l = 0; l < n; l++) {
            //std::cout<<"Point 444"<<std::endl;
            sum.ModAddEq(temp[l], mod);  //sum = sum + temp[l]
        }
        inner.ModAddEq(sum, mod);
    }
    // inner = q/4 m - q/8 + error

    //std::cout<<"q/8 = "<<(mod / (p * 2))<<std::endl;  //128
    // m = Round(4/q (q/4 m - q/8) ) =  Floor(4/q (q/4 m - q/8 + error + q/8+q/8) )
    //= Floor(4/q (q/4 m - q/8 + error + q/4) )
    inner.ModAddFastEq((mod / p), mod);

    *result = ((NativeInteger(p) * inner) / mod).ConvertToInt();

#if defined(WITH_NOISE_DEBUG)
    //Noise
    int q              = ct->GetModulus().ConvertToInt();
    NativeInteger temp = inner.ModSubFastEq((mod / (p * 2)), mod);
    ;  //cF
    NativeInteger ans(*result);
    // cout<<"ans="<<ans<<endl;
    temp.ModSubFastEq(NativeVector::Integer(ans * mod / 4), mod);  // cF - q/4 * m  =  e
    int err = temp.ConvertToInt();
    if (err > (q / 2)) {
        err = err - q;
    }
    std::cerr << err <<",";
#endif
}

MNTRUCiphertext MNTRUEncryptionScheme::ModSwitch(NativeInteger q, ConstMNTRUCiphertext& ctQ) const {
    auto n = ctQ->GetLength();
    // cout<<"n  = "<<n<<endl;
    auto Q = ctQ->GetModulus();
    auto k = ctQ->Getk();
    std::vector<NativeVector> c(k, NativeVector(n, q));

    for (uint32_t i = 0; i < k; i++) {
        for (size_t j = 0; j < n; j++) {
            c[i][j] = RoundqQ(ctQ->GetElements()[i][j], q, Q);
        }
    }

    return std::make_shared<MNTRUCiphertextImpl>(MNTRUCiphertextImpl(std::move(c)));
}

std::vector<NativeVector> MNTRUEncryptionScheme::MatrixMultiply(const std::vector<NativeVector>& A,
                                                                const std::vector<NativeVector>& B,
                                                                const NativeInteger mod) const {
    // 获取矩阵的行列信息
    size_t numRowsA = A.size();
    size_t numColsA = A[0].GetLength();
    size_t numRowsB = B.size();
    size_t numColsB = B[0].GetLength();

    // 检查矩阵是否可以相乘
    if (numColsA != numRowsB) {
        std::cerr << "Error: Incompatible matrix dimensions for multiplication." << std::endl;
        exit(1);
    }

    // 创建结果矩阵并初始化为零矩阵
    std::vector<NativeVector> result(numRowsA, NativeVector(numColsB, mod));
    NativeInteger temp(0);
    // 执行矩阵乘法
    for (size_t i = 0; i < numRowsA; ++i) {
        for (size_t j = 0; j < numColsB; ++j) {
            for (size_t k = 0; k < numColsA; ++k) {
                temp = A[i][k].ModMul(B[k][j], mod);
                result[i][j].ModAddEq(temp, mod);
            }
        }
    }

    return result;
}


void MNTRUEncryptionScheme::mod_q(NativeVector& output, std::vector<long>& input,const long q) const
{
    // output.resize(input.size());
    for (size_t i = 0; i < input.size(); i++){
        int32_t coef = input[i]%q;
        if (coef < 0)
            coef +=q;
        output[i] = typename NativeVector::Integer(coef);
        // NativeInteger(coef);
    }
}


MNTRUSwitchingKey MNTRUEncryptionScheme::KeySwitchGen(const std::shared_ptr<MNTRUCryptoParams>& params,
                                                      ConstMNTRUPrivateKey& sk,
                                                      const std::vector<NativeVector> skN) const {
    // std::cout<<"In mntru-pke.cpp KeySwitchGen:"<<std::endl;
    uint32_t n               = params->Getn();
    uint32_t N               = params->GetN();
    uint32_t k               = params->Getk();
    const NativeInteger& qKS = params->GetqKS();
    const long qKS_long = qKS.ConvertToInt();
    // NativeInteger::Integer value{1};
    NativeInteger::Integer baseKS(params->GetBaseKS());
    // cout<<"Bks = "<<baseKS<<endl;
    // NativeInteger baseKS = NativeInteger(params->GetBaseKS());

    const auto digitCount =
        static_cast<size_t>(std::ceil(log(qKS.ConvertToDouble()) / log(static_cast<double>(baseKS))));
    // std::cout<<"digitCount = "<<digitCount<<std::endl;
    // std::cout<<"n,N,k = "<<n<<" "<<" "<<N<<" "<<k<<std::endl;

    std::vector<NativeVector> s = skN;  //k个

    // cout<<"第二层私钥 k个N长多项式"<<endl;
    // for(uint32_t i=0;i<s.size();i++){//N*d
    //     cout<<s[i]<<endl;
    //  }


    std::vector<std::vector<NativeVector>> KSK(k,std::vector<NativeVector>(N*digitCount,NativeVector(n,qKS)));


    std::vector<std::vector<std::vector<long>>> ksk_long(k,std::vector<std::vector<long>>(N*digitCount,std::vector<long>(n)));

    for (uint32_t u = 0; u < k; u++) {
        //cout<<"u = "<<u<<endl;
//NativePoly(params->GetDgg(), polyParams, Format::COEFFICIENT)
         
          std::vector<NativeVector> E(N * digitCount, params->GetDggKS().GenerateVector(n, qKS));
       //  std::vector<NativeVector> E(N * digitCount, NativeVector(n, qKS));

      //  cout<<E[0]<<endl;
        s[u].SwitchModulus(qKS);
        

        std::vector<std::vector<long>> E_long(N * digitCount, std::vector<long>(n));

        
        // NativeInteger::Integer coef_w_pwr{s[u][0]};
        NativeInteger coef_w_pwr{s[u][0]};
        // std::cout<<"coef_w_pwr = "<<coef_w_pwr<<std::endl;
        for (uint32_t i = 0; i < digitCount; i++)  //d
        {
            //cout<<" i = "<<i;
            // std::cout<<"E[i][0] = "<<E[i][0]<<std::endl;
            E[i][0].ModAddEq(coef_w_pwr,qKS);
            // std::cout<<"E[i][0] + coef_w_pwr = "<<E[i][0]<<std::endl;
            // std::cout<<"coef_w_pwr = "<<coef_w_pwr<<std::endl;
            coef_w_pwr *= baseKS;
            // std::cout<<"coef_w_pwr = "<<coef_w_pwr<<std::endl;
        }
        //cout<<endl;
        for (uint32_t i = 1; i < N; i++)//2048
        {
            //cout<<" i = "<<i;
            coef_w_pwr = NativeInteger::Integer{0};
            // coef_w_pwr.ModSubEq(s[u][N-i],qKS);
            coef_w_pwr.ModAddEq(s[u][i],qKS);
            for (uint32_t j = 0; j < digitCount; j++)
            {
                E[i*digitCount+j][0].ModAddEq(coef_w_pwr,qKS);
                coef_w_pwr *= baseKS;
            }
        }
        //cout<<endl;
        //E_long赋值
        for(uint32_t i= 0 ;i<N * digitCount;i++)
        {
            for(uint32_t j=0;j<n;j++)
            {
                long temp = E[i][j].ConvertToInt();
                if(temp > qKS_long/2)
                {
                    temp -= qKS_long;
                    //cout<<"temp = "<<temp<<endl;
                }
                E_long[i][j] = temp;
            }
        }


         // parameters of the block optimization of matrix multiplication
        uint32_t block = 4;   
        uint32_t blocks = (n/block)*block;   // 600
        uint32_t rem_block = n%block;   // 0

        //cout<<"block = "<<block<<endl;

        //cout<<"blocks = "<<blocks<<endl;

        //cout<<"rem_block = "<<rem_block<<endl;

        // (G + P * Phi(f) * E) * F^(-1) as in the paper
        auto sk_inv = sk->GetF_inv()[u];


        for (uint32_t i = 0; i < N*digitCount; i++)//2048
        {
            // if(i%10==0){
            //     //cout<<" i = "<<i;
            //     //cout<<" ***************** "<<endl;
            // }
            vector<long>& k_row = ksk_long[u][i];
            vector<long>& g_row = E_long[i];
            for (uint32_t l = 0; l < n; l++)//600
            {
                // if(l%100==0)
                // cout<<" l = "<<l;
                NativeVector& f_row = sk_inv[l]; //行
                //cout << "j: " << j << endl;
                auto coef = g_row[l];
                for (uint32_t j = 0; j < blocks; j+=block)
                {
                    //cout<<"j = "<<j<<endl;
                    long fj =  f_row[j].ConvertToInt();
                    long fj1 =  f_row[j+1].ConvertToInt();
                    long fj2 =  f_row[j+2].ConvertToInt();
                    long fj3 =  f_row[j+3].ConvertToInt();
                    fj = (fj>qKS_long/2)? fj-qKS_long:fj;
                    fj1 = (fj1>qKS_long/2)? fj1-qKS_long:fj1;
                    fj2 = (fj2>qKS_long/2)? fj2-qKS_long:fj2;
                    fj3 = (fj3>qKS_long/2)? fj3-qKS_long:fj3;
                    k_row[j] += (coef * fj);
                    k_row[j+1] += (coef * fj1);
                    k_row[j+2] += (coef * fj2);
                    k_row[j+3] += (coef * fj3);
                }
                for (uint32_t j = 0; j < rem_block; j++){
                    //cout<<"j = "<<j<<endl;
                    long fj =  f_row[blocks+j].ConvertToInt();
                    fj = (fj>qKS_long/2)? fj-qKS_long:fj;
                    k_row[blocks+j] += (coef * fj);
                }
                    
            }
        }
        for (uint32_t i = 0; i < N*digitCount; i++)//2048
        {
            mod_q(KSK[u][i],ksk_long[u][i],qKS_long);
        }
    }//end for u
    return std::make_shared<MNTRUSwitchingKeyImpl>(MNTRUSwitchingKeyImpl(KSK));
}


// version 0
MNTRUCiphertext MNTRUEncryptionScheme::KeySwitch(const std::shared_ptr<MNTRUCryptoParams>& params,
                                                 ConstMNTRUSwitchingKey& KSK, ConstMNTRUCiphertext& ctQN) const {
    //std::cout<<"In MNTRUEncryptionScheme KeySwitch"<<std::endl;
    uint32_t n = params->Getn();
    uint32_t N = params->GetN();
    uint32_t k = params->Getk();
    NativeInteger Q(params->GetqKS());
    NativeInteger::Integer baseKS(params->GetBaseKS());
    const auto digitCount = static_cast<size_t>(std::ceil(log(Q.ConvertToDouble()) / log(static_cast<double>(baseKS))));
    auto qKS = params->GetqKS();
    std::vector<NativeVector> c(k, NativeVector(n, Q));

    std::vector<NativeVector> ctQN_hat(k, NativeVector(N * digitCount, Q));

// //输出c
//     cout<<ctQN->GetElements()[0]<<endl;
//     cout<<ctQN->GetElements()[1]<<endl;

    //std::cout<<"digitCount = "<<digitCount<<std::endl;
    //std::cout<<"baseKS = "<<baseKS<<std::endl;
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(k))
    for (uint32_t u = 0; u < k; u++) {
        for (uint32_t i = 0; i < N; ++i) {  //N长的ctQN
            NativeInteger::Integer ctmp(ctQN->GetElements()[u][i].ConvertToInt());
            //std::cout<<"ctmp = "<<ctmp<<std::endl;
            //扩展d维度
            //std::cout<<"分解结果 = "<<std::endl;
            for (uint32_t j = 0; j < digitCount; ++j) {
                const auto c0 = (ctmp % baseKS);  //分解结果
                ctmp /= baseKS;
                ctQN_hat[u][i * digitCount + j] = c0;
                //std::cout<<ctQN_hat[u][i*digitCount+j]<<" ";
            }  // 27,17,2   27+32*17+32*32*2=2619
            //std::cout<<std::endl;
        }
        // cout<<"ctQN_hat:"<<endl;
        // cout<<ctQN_hat[u]<<endl;
        for (uint32_t i = 0; i < n; i++) {
            NativeInteger sum(0);
            // cout<<ctQN_hat[u].GetLength()<<endl;
            // cout<<KSK->GetElements_coli(i)[u].GetLength()<<endl;
            NativeVector temp = ctQN_hat[u].ModMul(KSK->GetElements_coli(i)[u]);
            // cout<<"temp.GetLength() = "<<temp.GetLength()<<endl;
            for (uint32_t l = 0; l < temp.GetLength(); l++) {
                sum.ModAddEq(temp[l], qKS);  //sum = sum + temp[l]
            }
            c[u][i] = sum;
        }
    }

    return std::make_shared<MNTRUCiphertextImpl>(MNTRUCiphertextImpl(std::move(c)));

    // return std::make_shared<MNTRUCiphertextImpl>(MNTRUCiphertextImpl());
}



// //version 1
// MNTRUCiphertext MNTRUEncryptionScheme::KeySwitch(const std::shared_ptr<MNTRUCryptoParams>& params,
//                                                  ConstMNTRUSwitchingKey& KSK, ConstMNTRUCiphertext& ctQN) const {
//     std::cout<<"In MNTRUEncryptionScheme KeySwitch"<<std::endl;
//     clock_t chushihua = clock();
//     uint32_t n = params->Getn();
//     uint32_t N = params->GetN();
//     uint32_t k = params->Getk();
//     NativeInteger Q(params->GetqKS());
//     long Q_long = Q.ConvertToInt<uint32_t>();
//     NativeInteger::Integer baseKS(params->GetBaseKS());
//     const auto digitCount = static_cast<size_t>(std::ceil(log(Q.ConvertToDouble()) / log(static_cast<double>(baseKS))));
//     std::vector<NativeVector> c(k, NativeVector(n, Q));
//     std::vector<std::vector<long>> ctQN_hat_long(k, std::vector<long>(N * digitCount));

//     std::cout << "初始化 in " << float(clock()-chushihua)*1000/CLOCKS_PER_SEC<<"ms" << std::endl;
//     for (uint32_t u = 0; u < k; u++) {
//         // std::cout<<"ctQN_hat_long"<<endl;
//         clock_t startdec = clock();
//         for (uint32_t i = 0; i < N; ++i) {  //N长的ctQN
//             auto ctmp(ctQN->GetElements()[u][i].ConvertToInt<uint32_t>());
//             for (uint32_t j = 0; j < digitCount; ++j) {
//                 const auto c0 = (ctmp % baseKS);  //分解结果
//                 ctmp /= baseKS;
//                 // ctQN_hat[u][i * digitCount + j] = c0;
//                 long c0_long = c0;
//                 c0_long = c0_long>Q_long/2? (c0_long-Q_long):(c0_long);
//                 ctQN_hat_long[u][i * digitCount + j] = c0_long;
//                 // std::cout<<ctQN_hat_long[u][i*digitCount+j]<<" ";
//             }  // 27,17,2   27+32*17+32*32*2=2619
//             // std::cout<<std::endl;
//         }
//         std::cout << "分解 in " << float(clock()-startdec)*1000/CLOCKS_PER_SEC<<"ms" << std::endl;
//         // cout<<"ctQN_hat:"<<endl;
//         // cout<<ctQN_hat[u]<<endl;
//         clock_t start = clock();
//         for (uint32_t i = 0; i < n; i++) {
//             // NativeInteger sum(0);

//             // cout<<"KSK->GetElements_coli(i)[u] = "<<KSK->GetElements_coli(i)[u]<<endl;

//             long sum1_long = 0;
//             for(uint32_t j=0;j<N*digitCount;j++){
//                 long ksk_long = KSK->GetElements_coli(i)[u][j].ConvertToInt<uint32_t>();
//                 sum1_long += ksk_long*ctQN_hat_long[u][j];
//             }
//             sum1_long %=Q_long;
//             sum1_long = sum1_long<0?(sum1_long+Q_long):(sum1_long);
//             // cout<<"sum1_long  = " <<sum1_long<<endl;
//             // NativeVector temp = ctQN_hat[u].ModMul(KSK->GetElements_coli(i)[u]);
//             // // cout<<"temp.GetLength() = "<<temp.GetLength()<<endl;
//             // for (uint32_t l = 0; l < temp.GetLength(); l++) {
//             //     sum.ModAddEq(temp[l], qKS);  //sum = sum + temp[l]
//             // }
//             // cout<<"ctN * KSK = "<<sum<<endl;
//             c[u][i] = typename NativeVector::Integer(sum1_long);
//         }
//         std::cout << "矩阵乘法 in " << float(clock()-start)*1000/CLOCKS_PER_SEC<<"ms" << std::endl;
//     }
//     return std::make_shared<MNTRUCiphertextImpl>(MNTRUCiphertextImpl(std::move(c)));
// }



void MNTRUEncryptionScheme::EvalSubEq(MNTRUCiphertext& ct1, ConstMNTRUCiphertext& ct2) const {
    auto k = ct1->Getk();
    for (uint32_t i = 0; i < k; i++) {
        ct1->GetElements()[i].ModSubEq(ct2->GetElements()[i]);
    }
}

void MNTRUEncryptionScheme::EvalAddEq(MNTRUCiphertext& ct1, ConstMNTRUCiphertext& ct2) const {
    auto k = ct1->Getk();
    for (uint32_t i = 0; i < k; i++) {
        ct1->GetElements()[i].ModAddEq(ct2->GetElements()[i]);
    }
}

};  // namespace lbcrypto
