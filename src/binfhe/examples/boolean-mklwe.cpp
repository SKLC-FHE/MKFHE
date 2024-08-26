
#include "binfhecontext.h"

using namespace lbcrypto;
using namespace std;

#define WITH_NOISE_DEBUG

int main() {
    // Sample Program: Step 1: Set CryptoContext
    auto cc = BinFHEContext();

    cc.GenerateBinFHEContext(STD100_MKNTRU_LWE, MKNTRU_LWE);
    cout<<"Generating sk"<<endl;
   
    auto sk = cc.MKLWE_KeyGen();


    int m0=0;
    int m1=1;
    MKLWECiphertext ct1 = cc.Encrypt(sk, m0);
    MKLWECiphertext ct2 = cc.Encrypt(sk, m1);

    MKLWEPlaintext  result;


    // Generate the bootstrapping keys (refresh and switching keys)
    std::cout << "Generating the bootstrapping keys..." << std::endl;
    cc.MKBTKeyGen(sk);
    std::cout << "Completed the key generation." << std::endl;


    clock_t start = clock();
    MKLWECiphertext ctOUT = cc.EvalBinGate(NAND, ct1, ct2);
    std::cout<<"Time of gate bootstrapping:\t" << float(clock()-start)*1000/CLOCKS_PER_SEC<<"ms" << std::endl;


    cc.Decrypt(sk, ctOUT, &result);
    std::cout << "Result of encrypted computation of ( "<<m0<<" NAND "<<m1<<" ) = " << result << std::endl;
   
    return 0;
}
