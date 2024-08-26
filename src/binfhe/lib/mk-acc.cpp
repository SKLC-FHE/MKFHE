
#include "lattice/lat-hal.h"
#include "mk-acc.h"
#include <memory>
#include <vector>


namespace lbcrypto {

void UniEncAccumulator::SignedDigitDecompose(const std::shared_ptr<UniEncCryptoParams>& params,
                                              const std::vector<NativePoly>& input,
                                              std::vector<NativePoly>& output) const 
{
    
    auto QHalf{params->GetQ().ConvertToInt<BasicInteger>() >> 1};
    auto Q_int{params->GetQ().ConvertToInt<NativeInteger::SignedNativeInt>()};
    auto gBits{static_cast<NativeInteger::SignedNativeInt>(__builtin_ctz(params->GetBaseG()))};
    auto gBitsMaxBits{static_cast<NativeInteger::SignedNativeInt>(NativeInteger::MaxBits() - gBits)};
    // approximate gadget decomposition is used; the first digit is ignored
    uint32_t digitsG2{(params->GetDigitsG() - 1) << 1};
    uint32_t N{params->GetN()};

    for (uint32_t k{0}; k < N; ++k) {
       
        auto t0{input[0][k].ConvertToInt<BasicInteger>()};
        auto d0{static_cast<NativeInteger::SignedNativeInt>(t0 < QHalf ? t0 : t0 - Q_int)};
        auto t1{input[1][k].ConvertToInt<BasicInteger>()};
        auto d1{static_cast<NativeInteger::SignedNativeInt>(t1 < QHalf ? t1 : t1 - Q_int)};

       
        auto r0{(d0 << gBitsMaxBits) >> gBitsMaxBits};
        d0 = (d0 - r0) >> gBits;

        auto r1{(d1 << gBitsMaxBits) >> gBitsMaxBits};
        d1 = (d1 - r1) >> gBits;

        for (uint32_t d{0}; d < digitsG2; d += 2) {
            r0 = (d0 << gBitsMaxBits) >> gBitsMaxBits;
            d0 = (d0 - r0) >> gBits;
            if (r0 < 0)
                r0 += Q_int;
            output[d + 0][k] += r0;

            r1 = (d1 << gBitsMaxBits) >> gBitsMaxBits;
            d1 = (d1 - r1) >> gBits;
            if (r1 < 0)
                r1 += Q_int;
            output[d + 1][k] += r1;
        }
    }
}

// Decompose a ring element, not ciphertext
void UniEncAccumulator::SignedDigitDecompose(const std::shared_ptr<UniEncCryptoParams>& params,
                                              const NativePoly& input, std::vector<NativePoly>& output) const 
{
    auto QHalf{params->GetQ().ConvertToInt<BasicInteger>() >> 1};
    auto Q_int{params->GetQ().ConvertToInt<NativeInteger::SignedNativeInt>()};
    auto gBits{static_cast<NativeInteger::SignedNativeInt>(__builtin_ctz(params->GetBaseG()))};
    auto gBitsMaxBits{static_cast<NativeInteger::SignedNativeInt>(NativeInteger::MaxBits() - gBits)};
    // approximate  is used; the first digit is ignored
    uint32_t digitsG{params->GetDigitsG() - 1};
    uint32_t N{params->GetN()};

    for (uint32_t k{0}; k < N; ++k) {
        auto t0{input[k].ConvertToInt<BasicInteger>()};
        auto d0{static_cast<NativeInteger::SignedNativeInt>(t0 < QHalf ? t0 : t0 - Q_int)};

        auto r0{(d0 << gBitsMaxBits) >> gBitsMaxBits};
        d0 = (d0 - r0) >> gBits;

        for (uint32_t d{0}; d < digitsG; ++d) {
            r0 = (d0 << gBitsMaxBits) >> gBitsMaxBits;
            d0 = (d0 - r0) >> gBits;
            if (r0 < 0)
                r0 += Q_int;
            output[d][k] += r0;
        }
    }
}

};  // namespace lbcrypto
