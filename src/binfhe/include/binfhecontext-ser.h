

#ifndef BINFHE_BINFHECONTEXT_SER_H
#define BINFHE_BINFHECONTEXT_SER_H

#include "binfhecontext.h"
#include "utils/serial.h"

// Registers types needed for serialization
CEREAL_REGISTER_TYPE(lbcrypto::LWECryptoParams);
CEREAL_REGISTER_TYPE(lbcrypto::LWECiphertextImpl);
CEREAL_REGISTER_TYPE(lbcrypto::LWEPrivateKeyImpl);
CEREAL_REGISTER_TYPE(lbcrypto::LWEPublicKeyImpl);
CEREAL_REGISTER_TYPE(lbcrypto::LWESwitchingKeyImpl);
CEREAL_REGISTER_TYPE(lbcrypto::RLWECiphertextImpl);
CEREAL_REGISTER_TYPE(lbcrypto::RingGSWCryptoParams);
CEREAL_REGISTER_TYPE(lbcrypto::RingGSWEvalKeyImpl);
CEREAL_REGISTER_TYPE(lbcrypto::RingGSWACCKeyImpl);
CEREAL_REGISTER_TYPE(lbcrypto::BinFHECryptoParams);
CEREAL_REGISTER_TYPE(lbcrypto::BinFHEContext);
CEREAL_REGISTER_TYPE(lbcrypto::NTRUCiphertextImpl);
CEREAL_REGISTER_TYPE(lbcrypto::VectorNTRUCryptoParams);
CEREAL_REGISTER_TYPE(lbcrypto::VectorNTRUEvalKeyImpl);
CEREAL_REGISTER_TYPE(lbcrypto::VectorNTRUACCKeyImpl);
#endif
