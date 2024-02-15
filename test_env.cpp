#include <iostream>
#include <iomanip>
#include <openssl/opensslv.h>
#include <secp256k1.h>

int main() {
    std::cout << "\033[1;34m--- CRYPTON-CORE: ENVIRONMENT CHECK ---\033[0m" << std::endl;

    // 1. Versión del Compilador
    std::cout << "GCC Version: " << __VERSION__ << std::endl;

    // 2. Versión de OpenSSL
    std::cout << "OpenSSL Version: " << OPENSSL_VERSION_TEXT << std::endl;

    // 3. Verificación de Arquitectura (Crucial para __int128)
    std::cout << "Arch: " << (sizeof(void*) * 8) << "-bit";
    #ifdef __SIZEOF_INT128__
        std::cout << " (Native int128 support detected)" << std::endl;
    #else
        std::cout << " (Warning: No native int128)" << std::endl;
    #endif

    // 4. Test de secp256k1
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    if (ctx) {
        std::cout << "\033[1;32msecp256k1 Context: OK (Initialized)\033[0m" << std::endl;
        secp256k1_context_destroy(ctx);
    } else {
        std::cerr << "\033[1;31msecp256k1 Context: FAILED\033[0m" << std::endl;
        return 1;
    }

    std::cout << "\033[1;34m---------------------------------------\033[0m" << std::endl;
    return 0;
}