
#include <ostream>

#include "binfhe-constants.h"

namespace lbcrypto {

std::ostream& operator<<(std::ostream& s, BINFHE_PARAMSET f) {
    switch (f) {
        case TOY:
            s << "TOY";
            break;
        case MEDIUM:
            s << "MEDIUM";
            break;
        case STD128_LMKCDEY:
            s << "STD128_LMKCDEY";
            break;
        case STD128_AP:
            s << "STD128_AP";
            break;
        case STD128:
            s << "STD128";
            break;
        case STD192:
            s << "STD192";
            break;
        case STD256:
            s << "STD256";
            break;
        case STD128Q:
            s << "STD128Q";
            break;
        case STD128Q_LMKCDEY:
            s << "STD128Q_LMKCDEY";
            break;
        case STD192Q:
            s << "STD192Q";
            break;
        case STD256Q:
            s << "STD256Q";
            break;
        case STD128_3:
            s << "STD128_3";
            break;
        case STD128_3_LMKCDEY:
            s << "STD128_3_LMKCDEY";
            break;
        case STD128Q_3:
            s << "STD128Q_3";
            break;
        case STD128Q_3_LMKCDEY:
            s << "STD128Q_3_LMKCDEY";
            break;
        case STD192Q_3:
            s << "STD192Q_3";
            break;
        case STD256Q_3:
            s << "STD256Q_3";
            break;
        case STD128_4:
            s << "STD128_4";
            break;
        case STD128_4_LMKCDEY:
            s << "STD128_4_LMKCDEY";
            break;
        case STD128Q_4:
            s << "STD128Q_4";
            break;
        case STD128Q_4_LMKCDEY:
            s << "STD128Q_4_LMKCDEY";
            break;
        case STD192Q_4:
            s << "STD192Q_4";
            break;
        case STD256Q_4:
            s << "STD256Q_4";
            break;
        case SIGNED_MOD_TEST:
            s << "SIGNED_MOD_TEST";
            break;
        case P128T:
            s << "P128T";
            break;
        case P128G:
            s << "P128G";
            break;
        case P128T_2:
            s << "P128T_2";
            break;
        case P128G_2:
            s << "P128G_2";
            break;
        case STD128_LMKCDEY_New:
            s << "STD128_LMKCDEY_New";
            break;
        default:
            s << "UNKNOWN";
            break;
    }
    return s;
}

std::ostream& operator<<(std::ostream& s, BINFHE_OUTPUT f) {
    switch (f) {
        case FRESH:
            s << "FRESH";
            break;
        case BOOTSTRAPPED:
            s << "BOOTSTRAPPED";
            break;
        default:
            s << "UNKNOWN";
            break;
    }
    return s;
}

std::ostream& operator<<(std::ostream& s, BINFHE_METHOD f) {
    switch (f) {
        case AP:
            s << "DM";
            break;
        case GINX:
            s << "CGGI";
            break;
        case LMKCDEY:
            s << "LMKCDEY";
            break;
        default:
            s << "UNKNOWN";
            break;
    }
    return s;
}

std::ostream& operator<<(std::ostream& s, BINGATE f) {
    switch (f) {
        case OR:
            s << "OR";
            break;
        case AND:
            s << "AND";
            break;
        case NOR:
            s << "NOR";
            break;
        case NAND:
            s << "NAND";
            break;
        case XOR_FAST:
            s << "XOR_FAST";
            break;
        case XNOR_FAST:
            s << "XNOR_FAST";
            break;
        case XOR:
            s << "XOR";
            break;
        case XNOR:
            s << "XNOR";
            break;
        case AND3:
            s << "AND3";
            break;
        case OR3:
            s << "OR3";
            break;
        case AND4:
            s << "AND4";
            break;
        case OR4:
            s << "OR4";
            break;
        case MAJORITY:
            s << "MAJORITY";
            break;
        case CMUX:
            s << "CMUX";
            break;
        default:
            s << "UNKNOWN";
            break;
    }
    return s;
}

};  // namespace lbcrypto
