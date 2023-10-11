#pragma once

#ifndef XORV
#define XORV

#include <type_traits>
#include <utility>
#include <random>
#include <intrin.h>

// minimum size of the xor buffer for each xor'd item
// NOTE: values too high will make compilation very slow, values below 32 (or 16) will make decompilation much simpler
#define MIN_XOR_SIZE (16)
// maximum randomness size of the xor buffer for each xor'd item
// NOTE: values too high will make compilation very slow
#define RANDOMNESS_SIZE (16)
// enable this if you want to really mess with decompilation...
#define DECRYPT_ULTRA 0
// alignment types (up to 0x20 -> faster decryption)
#define XOR_ALIGNMENT_BYTES 0x20
// get the encrypted value buffer; to decrypt, call buffer.val<type>(); with the respective type; also works with string pointers
#define xv(value) xor_value_internal((value), __LINE__)
// decrypt the encrypted value buffer automatically at runtime
#define _xv(value) xor_value_internal((value), __LINE__).val<decltype((value))>()
// decrypt an encrypted string buffer automatically at runtime; the provided buffer is stack and r/w
#define _xs(value) xor_value_internal((value), __LINE__).valarray<std::add_pointer_t<std::remove_const_t<std::remove_reference_t<decltype(*std::begin(std::declval<decltype((value))&>()))>>>>()
// (CONST) decrypt an encrypted string buffer automatically at runtime; the provided buffer is stack and readonly
#define _xcs(value) xor_value_internal((value), __LINE__).valarray<std::add_pointer_t<std::remove_reference_t<decltype(*std::begin(std::declval<decltype((value))&>()))>>>()

#define max(a, b) ((a > b) ? (a) : (b))
// generates a random number seeded with time and the custom seed
#define RAND_NEXT (PSEUDO_RANDOM)
// generates a random number seeded with time and the custom seed between min and max ( [min, max[ )
#define RAND_NEXT_BETWEEN(low, high) (low + (PSEUDO_RANDOM % (high - low)))
// generates a random number seeded with time and the custom seed with a limit ( [0, limit[ )
#define RAND_NEXT_LIMIT(limit) RAND_NEXT_BETWEEN(0, max(1, limit))

#pragma warning( disable : 26450 )
#define PSEUDO_RANDOM_SEEDED(x) ((((x + 6906969069ULL) ^ (x + (1234567ULL * (961487658934543ULL ^ x) * (1066149217761811ULL * x)))) + (0x3c4f01355a2a1ba4ULL >> (x % 9))) + (x % 89) ^ (x % 65537))
#define PSEUDO_RANDOM PSEUDO_RANDOM_SEEDED(__COUNTER__)

template <char ... Buffer>
struct Value {

#if !DECRYPT_ULTRA
    __forceinline void xor_buffers(char* buf, char* valbuf, size_t typesize) {
        size_t idx = 0;
        size_t sizeleft = typesize;

        while (sizeleft >= 32) {
            __m256i x = _mm256_loadu_si256((const __m256i*) & buf[idx]);
            __m256i v = _mm256_loadu_si256((const __m256i*) & valbuf[idx]);
            _mm256_store_si256((__m256i*) & valbuf[idx], _mm256_xor_si256(x, v));
            idx += 32;
            sizeleft -= 32;
        }

#if (XOR_ALIGNMENT_BYTES % 32 != 0)
        while (sizeleft >= 16) {
            __m128i x = _mm_loadu_si128((const __m128i*) & buf[idx]);
            __m128i v = _mm_loadu_si128((const __m128i*) & valbuf[idx]);
            _mm_store_si128((__m128i*) & valbuf[idx], _mm_xor_si128(x, v));
            idx += 16;
            sizeleft -= 16;
        }
#endif
#if (XOR_ALIGNMENT_BYTES % 16 != 0)
        while (sizeleft >= 8) {
            unsigned __int64 x = *(unsigned __int64*)&buf[idx];
            unsigned __int64 v = *(unsigned __int64*)&valbuf[idx];
            *(unsigned __int64*)&valbuf[idx] = x ^ v;
            idx += 8;
            sizeleft -= 8;
        }
#endif
#if (XOR_ALIGNMENT_BYTES % 8 != 0)
        while (sizeleft >= 4) {
            unsigned int x = *(unsigned int*)&buf[idx];
            unsigned int v = *(unsigned int*)&valbuf[idx];
            *(unsigned int*)&valbuf[idx] = x ^ v;
            idx += 4;
            sizeleft -= 4;
        }
#endif
#if (XOR_ALIGNMENT_BYTES % 4 != 0)
        while (sizeleft >= 2) {
            unsigned short x = *(unsigned short*)&buf[idx];
            unsigned short v = *(unsigned short*)&valbuf[idx];
            *(unsigned short*)&valbuf[idx] = x ^ v;
            idx += 2;
            sizeleft -= 2;
        }
#endif
#if (XOR_ALIGNMENT_BYTES % 2 != 0)
        while (sizeleft >= 1) {
            unsigned char x = *(unsigned char*)&buf[idx];
            unsigned char v = *(unsigned char*)&valbuf[idx];
            *(unsigned char*)&valbuf[idx] = x ^ v;
            idx += 1;
            sizeleft -= 1;
        }
#endif
    }
#else
    __forceinline void xor_buffers(char* buf, char* valbuf, size_t typesize) {
        size_t idx = 0;
        size_t sizeleft = typesize;

        while (sizeleft >= 16) {
            char val = buf[idx + (buf[idx] % 16)];
            if (val < 0) val *= -1;
            if (val < 0) val = 0;

            switch (val % 4) {
            case 0: {
                if (val > val < ((RAND_NEXT_LIMIT(buf[3] * 0x7F) + val) % 0x80) && sizeleft >= 32) {
                    __m256i x = _mm256_loadu_si256((const __m256i*) & buf[idx]);
                    __m256i v = _mm256_loadu_si256((const __m256i*) & valbuf[idx]);
                    _mm256_store_si256((__m256i*) & valbuf[idx], _mm256_xor_si256(x, v));
                    idx += 32;
                    sizeleft -= 32;
                }
                if (sizeleft >= 16) {
                    __m128i x = _mm_loadu_si128((const __m128i*) & buf[idx]);
                    __m128i v = _mm_loadu_si128((const __m128i*) & valbuf[idx]);
                    _mm_store_si128((__m128i*) & valbuf[idx], _mm_xor_si128(x, v));
                    idx += 16;
                    sizeleft -= 16;
                    int random = RAND_NEXT_BETWEEN(0, 4);
                    if (val < val < ((RAND_NEXT_LIMIT(buf[5] * 0x7F) + val) % 0x80) && sizeleft > random * 32) {
                        for (int i = 0; i < random * 32; i += 32) {
                            if (val < val < ((RAND_NEXT_LIMIT(buf[1] * 0x7F) + val) % 0x80)) {
                                __m256i x = _mm256_loadu_si256((const __m256i*) & buf[idx]);
                                __m256i v = _mm256_loadu_si256((const __m256i*) & valbuf[idx]);
                                _mm256_store_si256((__m256i*) & valbuf[idx], _mm256_xor_si256(x, v));
                                idx += 32;
                                sizeleft -= 32;
                            }
                        }
                    }
                }
                break;
            }
            case 1: {
                if (sizeleft >= 16) {
                    __m128i x = _mm_loadu_si128((const __m128i*) & buf[idx]);
                    __m128i v = _mm_loadu_si128((const __m128i*) & valbuf[idx]);
                    _mm_store_si128((__m128i*) & valbuf[idx], _mm_xor_si128(x, v));
                    idx += 16;
                    sizeleft -= 16;
                    int random = RAND_NEXT_BETWEEN(0, 3);
                    if (val < ((RAND_NEXT_LIMIT(buf[1] * 0x7F) + val) % 0x80) && sizeleft > random * 32) {
                        for (int i = 0; i < random * 32; i += 32) {
                            if (val < ((RAND_NEXT_LIMIT(buf[2] * 0x7F) + val) % 0x80)) {
                                __m256i x = _mm256_loadu_si256((const __m256i*) & buf[idx]);
                                __m256i v = _mm256_loadu_si256((const __m256i*) & valbuf[idx]);
                                _mm256_store_si256((__m256i*) & valbuf[idx], _mm256_xor_si256(x, v));
                                idx += 32;
                                sizeleft -= 32;
                            }
                        }
                    }
                }
                if (val > val < ((RAND_NEXT_LIMIT(buf[7] * 0x7F) + val) % 0x80) && sizeleft >= 32) {
                    while (sizeleft >= 32) {
                        __m256i x = _mm256_loadu_si256((const __m256i*) & buf[idx]);
                        __m256i v = _mm256_loadu_si256((const __m256i*) & valbuf[idx]);
                        _mm256_store_si256((__m256i*) & valbuf[idx], _mm256_xor_si256(x, v));
                        idx += 32;
                        sizeleft -= 32;
                    }
                }
                break;
            }
            case 2: {
                unsigned __int64 x = *(unsigned __int64*)&buf[idx];
                unsigned __int64 v = *(unsigned __int64*)&valbuf[idx];
                *(unsigned __int64*)&valbuf[idx] = x ^ v;
                idx += 8;
                sizeleft -= 8;
                if (sizeleft >= 8) {
                    unsigned __int64 x = *(unsigned __int64*)&buf[idx];
                    unsigned __int64 v = *(unsigned __int64*)&valbuf[idx];
                    *(unsigned __int64*)&valbuf[idx] = x ^ v;
                    idx += 8;
                    sizeleft -= 8;
                }
                if (buf[0] != 0 && val > val < ((RAND_NEXT_LIMIT(buf[0] * 0x7F) + val) % 0x80) && sizeleft >= 32) {
                    __m256i x = _mm256_loadu_si256((const __m256i*) & buf[idx]);
                    __m256i v = _mm256_loadu_si256((const __m256i*) & valbuf[idx]);
                    _mm256_store_si256((__m256i*) & valbuf[idx], _mm256_xor_si256(x, v));
                    idx += 32;
                    sizeleft -= 32;
                }
                break;
            }
            case 3: {
                __m128i x = _mm_loadu_si128((const __m128i*) & buf[idx]);
                __m128i v = _mm_loadu_si128((const __m128i*) & valbuf[idx]);
                _mm_store_si128((__m128i*) & valbuf[idx], _mm_xor_si128(x, v));
                idx += 16;
                sizeleft -= 16;
                break;
            }
            }
        }

#if (XOR_ALIGNMENT_BYTES % 16 != 0)
        while (sizeleft >= 8) {
            unsigned __int64 x = *(unsigned __int64*)&buf[idx];
            unsigned __int64 v = *(unsigned __int64*)&buf[idx + typesize];
            *(unsigned __int64*)&buf[idx + typesize] = x ^ v;
            idx += 8;
            sizeleft -= 8;
        }
#endif
#if (XOR_ALIGNMENT_BYTES % 8 != 0)
        while (sizeleft >= 4) {
            unsigned int x = *(unsigned int*)&buf[idx];
            unsigned int v = *(unsigned int*)&buf[idx + typesize];
            *(unsigned int*)&buf[idx + typesize] = x ^ v;
            idx += 4;
            sizeleft -= 4;
        }
#endif
#if (XOR_ALIGNMENT_BYTES % 4 != 0)
        while (sizeleft >= 2) {
            unsigned short x = *(unsigned short*)&buf[idx];
            unsigned short v = *(unsigned short*)&buf[idx + typesize];
            *(unsigned short*)&buf[idx + typesize] = x ^ v;
            idx += 2;
            sizeleft -= 2;
        }
#endif
#if (XOR_ALIGNMENT_BYTES % 2 != 0)
        while (sizeleft >= 1) {
            unsigned char x = *(unsigned char*)&buf[idx];
            unsigned char v = *(unsigned char*)&buf[idx + typesize];
            *(unsigned char*)&buf[idx + typesize] = x ^ v;
            idx += 1;
            sizeleft -= 1;
        }
#endif
    }
#endif

    // get value of integer type from encrypted buffer
    template <typename T>
    __forceinline T val() {
        // string check; use _xs/_xcs for strings
        static_assert(std::is_scalar_v<T>);
        char buf[] = { Buffer... };
        size_t typesize = sizeof(buf) / 3;
        xor_buffers(buf, buf + typesize, typesize);
        xor_buffers(buf + typesize * 2, buf + typesize, typesize);
        return *(T*)&buf[typesize];
    }

    // get value of array type from encrypted buffer
    template <typename T>
    __forceinline T valarray() {
        char buf[] = { Buffer... };
        size_t typesize = sizeof(buf) / 3;
        xor_buffers(buf, buf + typesize, typesize);
        xor_buffers(buf + typesize * 2, buf + typesize, typesize);
        return (T)&buf[typesize];
    }
};

namespace xorv {
    // clear (with xor encryption)
    // only works on xorv-encrypted string buffers, otherwise potential access violation
    __forceinline void clear_encrypt(char* str) {
        for (int i = 0; str[i] != '\0'; i++) str[i] ^= str[i - 1];
    }
    __forceinline void clear_encrypt(wchar_t* str) {
        for (int i = 0; str[i] != L'\0'; i++) str[i] ^= str[i - 1];
    }

    // normal clear (zero)
    // works on any string
    __forceinline void clear(char* str) {
        for (int i = 0; str[i] != '\0'; i++) str[i] = 0;
    }
    __forceinline void clear(wchar_t* str) {
        for (int i = 0; str[i] != L'\0'; i++) str[i] = 0;
    }
};

template <typename Val, size_t ... indices>
__forceinline decltype(auto) build_val(std::index_sequence<indices...>) {
    return Value<Val().buf[indices]...>();
}

// c++17 or higher for float support on values
#if (_MSVC_LANG >= 201703L) || (__cplusplus >= 201703L)
constexpr char get_byte_double(double val, int byte) {
    unsigned __int64 int64 = __builtin_bit_cast(unsigned __int64, val);
    return (char)(int64 >> (byte * 8));
}

constexpr char get_byte_float(float val, int byte) {
    unsigned int int32 = __builtin_bit_cast(unsigned int, val);
    return (char)(int32 >> (byte * 8));
}
#endif

constexpr char get_byte_cstr(const char* val, int byte) {
    return val[byte];
}

constexpr char get_byte_wcstr(const wchar_t* val, int byte) {
    wchar_t wchar = val[byte / 2];
    if (byte % 2 == 0) return (char)wchar;
    return (char)(wchar >> 8);
}

constexpr char get_byte_integer(unsigned __int64 val, int byte) {
    return (char)(val >> (byte * 8));
}

// c++17 or higher for float support (and "if constexpr")
#if (_MSVC_LANG >= 201703L) || (__cplusplus >= 201703L)
template<typename T>
constexpr char get_byte(T val, int byte) {
    if constexpr (std::is_same_v<double, T>) {
        return get_byte_double(val, byte);
    }
    else if constexpr (std::is_same_v<float, T>) {
        return get_byte_float(val, byte);
    }
    else if constexpr (std::is_same_v<const char*, T>) {
        return get_byte_cstr(val, byte);
    }
    else if constexpr (std::is_same_v<const wchar_t*, T>) {
        return get_byte_wcstr(val, byte);
    }
    else {
        return get_byte_integer((unsigned __int64)val, byte);
    }
}
#else
template<typename T>
constexpr char get_byte(T val, int byte) {
    if (std::is_same_v<const char*, T>) {
        return get_byte_cstr((const char*)val, byte);
    }
    else if (std::is_same_v<const wchar_t*, T>) {
        return get_byte_wcstr((const wchar_t*)val, byte);
    }
    else {
        return get_byte_integer((unsigned __int64)val, byte);
    }
}
#endif

#define xor_value_internal(val, l) []{\
        const int random = (RAND_NEXT % (RANDOMNESS_SIZE + 1)); \
        const int alignment = max(XOR_ALIGNMENT_BYTES, 1); \
        const int partsize = (alignment - ((max(MIN_XOR_SIZE, sizeof(val)) + random) % alignment)) + (max(MIN_XOR_SIZE, sizeof(val)) + random); \
\
        struct Val { \
            char buf[partsize * 3] = {}; \
\
            constexpr Val() { \
               unsigned __int64 key = random + RAND_NEXT; \
                /* fill parts of buffer with xor key */ \
                for (int i = 0; i < partsize; i++) { \
                    buf[i] = (char)(key >> ((i * 8) % 64)); \
                    if (i % 8 == 7) key += RAND_NEXT; \
                } \
                key += RAND_NEXT; \
                for (int i = partsize * 2; i < partsize * 3; i++) { \
                    buf[i] = (char)(key >> ((i * 8) % 64)); \
                    if (i % 8 == 7) key += RAND_NEXT; \
                } \
                /* fill the unused/filler portion of the real data with junk */ \
                for (int i = partsize + sizeof(val); i < partsize * 2; i++) { \
                    const int xorindex = i - partsize; \
                    buf[i] = (char)(key >> ((i * 8) % 64)); \
                    if (i % 8 == 7) key += RAND_NEXT; \
                } \
                /* fill parts of buffer with real data (encrypted) */ \
                for (int i = partsize; i < partsize + sizeof(val); i++) { \
                    const int xorindex = i - partsize; \
                    buf[i] = get_byte(val, xorindex); \
                    buf[i] ^= buf[xorindex]; \
                    buf[i] ^= buf[i + partsize]; \
                } \
            } \
        };\
        return build_val<Val>(std::make_index_sequence<partsize * 3>());\
}()

#endif