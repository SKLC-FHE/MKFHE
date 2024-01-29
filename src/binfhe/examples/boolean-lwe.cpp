
#include "binfhecontext.h"

using namespace lbcrypto;
using namespace std;

#define WITH_NOISE_DEBUG

int main() {
    // Sample Program: Step 1: Set CryptoContext
    auto cc = BinFHEContext();

    cc.GenerateBinFHEContext(STD128_XZWDF_LWE, XZWDF_LWE);
    cout<<"Generating sk"<<endl;
    clock_t start = clock();
    auto sk = cc.MKLWE_KeyGen();
    std::cout << "Generate sk in " << float(clock()-start)*1000/CLOCKS_PER_SEC<<"ms" << std::endl;

    int m0=0;
    int m1=1;
    MKLWECiphertext ct1 = cc.Encrypt(sk, m0);
    MKLWECiphertext ct2 = cc.Encrypt(sk, m1);

    MNTRUPlaintext result;
    cc.Decrypt(sk, ct1, &result);
    std::cout << "Result of encrypted ct1 = " << result << std::endl;
    cc.Decrypt(sk, ct2, &result);
    std::cout << "Result of encrypted ct2 = " << result << std::endl;


    // Generate the bootstrapping keys (refresh and switching keys)
    std::cout << "Generating the bootstrapping keys..." << std::endl;
    cc.MKBTKeyGen(sk);
    std::cout << "Completed the key generation." << std::endl;


    clock_t start2 = clock();
    MKLWECiphertext ctOUT = cc.EvalBinGate(NAND, ct1, ct2);
    std::cout<<"\t gate bootstrapping:\t" << float(clock()-start2)*1000/CLOCKS_PER_SEC<<"ms" << std::endl;


    cc.Decrypt(sk, ctOUT, &result);
    std::cout << "Result of encrypted computation of ( "<<m0<<" NAND "<<m1<<" ) = " << result << std::endl;
   
    return 0;
}
