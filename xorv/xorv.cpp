#include "xorv.hpp"
#include <iostream>

int main() {
    // string tests
    auto str = _xs("ABCABCABC\nTest Test Test\nTest 2.!");
    auto longstr = _xs("Long String 1 Long String 2 Long String 3 Long String 4 Long String 5 Long String 6 Long String 7 Long String 8 Long String 9 Long String 10");
    auto widestr = _xs(L"ABCABCABC\nTest Test Test\nTest 2.!");
    printf("String: %s\n", str);
    printf("Long String: %s\n", longstr);
    printf("Wide String: %S\n", widestr);
    xorv::clear_encrypt(str);
    printf("Cleared-Encrypted String: %s\n", str);

    // value tests
    float flt = _xv(3.141592f);
    double dbl = _xv(3.14159265358979f);
    int i = _xv(999123456);
    printf("Float: %f\n", flt);
    printf("Double: %f\n", dbl);
    printf("Integer: %d\n", i);
    return 0;
}