#pragma once

#include <atomic>
#include <thread>
#include <vector>
#include <cstring>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>

#ifdef __linux__
#include <sched.h>
#endif

typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;

#define CACHE_LINE_SIZE 64
#define ALIGN_CACHE alignas(CACHE_LINE_SIZE)

struct SearchConfig {
    int num_threads = std::thread::hardware_concurrency();
    uint64_t base70 = (uint64_t)1 << 70;
    uint64_t C71 = 7544;
    uint64_t Steo = 82351536043346212ULL;
    uint64_t step = 14336;
    int64_t i_start = -1000000;
    int64_t i_end = 1000000;
    unsigned char target[20] = {0xf6,0xf5,0x43,0x1d,0x25,0xbb,0xf7,0xb1,0x2e,0x8a,
                                0xdd,0x9a,0xf5,0xe3,0x47,0x5c,0x44,0xa0,0xa5,0xb8};
    struct Anom { const char* name; uint64_t offset; };
    std::vector<Anom> anoms = {{"PURE",0},{"STEAK",7960},{"D-KNIGHT",143280},{"WARP",7960^5401}};
    int ch_start = 1, ch_end = 24;
};

class OptimizedEllipticSearch {
public:
    explicit OptimizedEllipticSearch(const SearchConfig& cfg) : config(cfg), found(false), active_threads(0) {}

    void run() {
        auto start_time = std::chrono::steady_clock::now();

        // step_pub precomputation
        secp256k1_context* ctx_temp = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
        secp256k1_pubkey step_pub;
        {
            unsigned char step_priv[32] = {0};
            uint64_t step_val = config.step;
            for (int i = 0; i < 8; ++i) step_priv[31 - i] = (step_val >> (i * 8)) & 0xFF;
            if (!secp256k1_ec_pubkey_create(ctx_temp, &step_pub, step_priv)) {
                std::cerr << "step_pub error\n";
                secp256k1_context_destroy(ctx_temp);
                return;
            }
        }
        secp256k1_context_destroy(ctx_temp);

        // Precomputed combinations
        struct Precomp { secp256k1_pubkey const_pub; uint64_t offset; int ch; const char* name; uint128_t val; } ALIGN_CACHE;
        size_t num_combos = config.anoms.size() * (config.ch_end - config.ch_start + 1);
        Precomp* precomp_raw = (Precomp*)aligned_alloc(CACHE_LINE_SIZE, num_combos * sizeof(Precomp));
        if (!precomp_raw) { std::cerr << "alloc failed\n"; return; }
        std::unique_ptr<Precomp, decltype(&free)> precomp(precomp_raw, free);

        size_t idx = 0;
        for (const auto& anom : config.anoms) {
            for (int ch = config.ch_start; ch <= config.ch_end; ++ch) {
                uint128_t const_val = (uint128_t)config.base70
                                    + (uint128_t)(config.Steo + anom.offset) * config.step
                                    + (uint128_t)(config.C71 + ch);
                unsigned char priv[32] = {0};
                for (int i = 0; i < 16; ++i) priv[31 - i] = (uint8_t)((const_val >> (i * 8)) & 0xFF);
                secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
                secp256k1_pubkey pub;
                if (secp256k1_ec_pubkey_create(ctx, &pub, priv)) {
                    precomp[idx++] = {pub, anom.offset, ch, anom.name, const_val};
                }
                secp256k1_context_destroy(ctx);
            }
        }
        num_combos = idx;

        int64_t total_i = config.i_end - config.i_start + 1;
        int64_t chunk = (total_i + config.num_threads - 1) / config.num_threads;
        std::vector<std::thread> threads;
        active_threads = config.num_threads;
        struct { ALIGN_CACHE std::atomic<int64_t> processed{0}; } progress;
        int64_t total_keys_approx = num_combos * total_i;

        auto worker = [&](int64_t start_i, int64_t end_i, int cpu_id) {
#ifdef __linux__
            cpu_set_t cpuset;
            CPU_ZERO(&cpuset);
            CPU_SET(cpu_id % config.num_threads, &cpuset);
            pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
#endif
            secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
            unsigned char sha[32], rmd[20], pub_ser[33];
            size_t pub_len = 33;
            uint64_t local_proc = 0;
            const uint64_t FLUSH = 65536;

            for (size_t c = 0; c < num_combos; ++c) {
                if (found.load(std::memory_order_relaxed)) break;
                if (c + 1 < num_combos) __builtin_prefetch(&precomp[c + 1], 0, 3);
                const auto& pc = precomp[c];

                int128_t first_signed = (int128_t)pc.val + (int128_t)start_i * config.step;
                if (first_signed < 0) continue;
                uint128_t first_priv = (uint128_t)first_signed;
                unsigned char first_bytes[32] = {0};
                for (int i = 0; i < 16; ++i) first_bytes[31 - i] = (uint8_t)((first_priv >> (i * 8)) & 0xFF);
                secp256k1_pubkey cur;
                if (!secp256k1_ec_pubkey_create(ctx, &cur, first_bytes)) continue;

                auto check = [&](const secp256k1_pubkey& p, uint128_t key, int64_t i_val) {
                    if (!secp256k1_ec_pubkey_serialize(ctx, pub_ser, &pub_len, &p, SECP256K1_EC_COMPRESSED)) return false;
                    SHA256(pub_ser, pub_len, sha);
                    RIPEMD160(sha, 32, rmd);
                    if (memcmp(rmd, config.target, 20) == 0) {
                        std::cout << "\n\033[1;32m⭐ MATCH: i=" << i_val << " | " << pc.name << " (ch=" << pc.ch << ") | PRIV: ";
                        for (int b = 0; b < 16; ++b) printf("%02x", (uint8_t)((key >> ((15 - b) * 8)) & 0xFF));
                        std::cout << "\033[0m\n";
                        return true;
                    }
                    return false;
                };

                if (check(cur, first_priv, start_i)) { found.store(true, std::memory_order_release); break; }
                ++local_proc;

                for (int64_t i = start_i + 1; i <= end_i; ++i) {
                    if (found.load(std::memory_order_relaxed)) break;
                    secp256k1_pubkey new_pub;
                    const secp256k1_pubkey* pts[2] = {&cur, &step_pub};
                    if (!secp256k1_ec_pubkey_combine(ctx, &new_pub, pts, 2)) continue;
                    cur = new_pub;
                    int128_t key_signed = (int128_t)pc.val + (int128_t)i * config.step;
                    if (key_signed < 0) continue;
                    uint128_t full_key = (uint128_t)key_signed;
                    if (check(cur, full_key, i)) { found.store(true, std::memory_order_release); break; }
                    ++local_proc;
                    if (local_proc >= FLUSH) {
                        progress.processed.fetch_add(local_proc, std::memory_order_relaxed);
                        local_proc = 0;
                    }
                }
            }
            if (local_proc) progress.processed.fetch_add(local_proc, std::memory_order_relaxed);
            secp256k1_context_destroy(ctx);
            active_threads.fetch_sub(1, std::memory_order_release);
        };

        for (int t = 0; t < config.num_threads; ++t) {
            int64_t start = config.i_start + t * chunk;
            int64_t end = std::min(start + chunk - 1, (int64_t)config.i_end);
            if (start > end) { active_threads.fetch_sub(1, std::memory_order_release); continue; }
            threads.emplace_back(worker, start, end, t);
        }

        while (!found.load(std::memory_order_acquire) && active_threads.load(std::memory_order_acquire) > 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            int64_t proc = progress.processed.load(std::memory_order_relaxed);
            std::cout << "\r\033[1;34mProcessed: " << proc << " / ~" << total_keys_approx << " keys\033[0m" << std::flush;
        }

        for (auto& th : threads) th.join();
        double elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - start_time).count();
        std::cout << "\nFinished in " << elapsed << " s\n";
    }

private:
    SearchConfig config;
    ALIGN_CACHE std::atomic<bool> found;
    std::atomic<int> active_threads;
};