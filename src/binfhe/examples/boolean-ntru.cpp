
#include "binfhecontext.h"

using namespace lbcrypto;
using namespace std;

#define WITH_NOISE_DEBUG

int main() {
    // Sample Program: Step 1: Set CryptoContext
    auto cc = BinFHEContext();


    cc.GenerateBinFHEContext(STD128_XZWDF, XZWDF);

    // Sample Program: Step 2: Key Generation
    cout<<"Generating sk"<<endl;
    clock_t start = clock();
    auto sk = cc.MNTRU_KeyGen();
    std::cout << "Generate sk in " << float(clock()-start)*1000/CLOCKS_PER_SEC<<"ms" << std::endl;

    int m0=0;
    int m1=0;

    std::cout << "Generating the bootstrapping keys..." << std::endl;
    cc.MKBTKeyGen(sk);
    std::cout << "Completed the key generation." << std::endl;
    cc.ctGateGen(sk,NAND);
    std::cout << "Completed the ctNAND." << std::endl;

    // Sample Program: Step 3: Encryption
    std::cout << "encrypting " << std::endl;
    auto ct1 = cc.Encrypt(sk, m0);
    auto ct2 = cc.Encrypt(sk, m1);


    MNTRUPlaintext result;


    /*----------自举-------------*/
    clock_t start2 = clock();
    MNTRUCiphertext ctOUT = cc.EvalBinGate(NAND, ct1, ct2);
    clock_t end = clock();
    std::cout <<" times of  gate bootstrapping:\t" <<  double(end-start2)*1000/CLOCKS_PER_SEC<<"ms" << std::endl;




    cc.Decrypt(sk, ctOUT, &result);

    std::cout << "Result of encrypted computation of ( "<<m0<<" NAND "<<m1<<" ) = " << result << std::endl;
    return 0;
}
