# CPU/Cache Optimization in Elliptic Curve Search: Performance Analysis

---

## Theoretical Execution Model

Let $N_h$ be the thread count, $N_a$ the number of precomputed combinations (anomalies × channels),  
and $M = i_{\text{end}} - i_{\text{start}} + 1$ the range of linear iterations.

Total execution time decomposes as:

$$
T_{\text{total}} = \frac{1}{N_h} \sum_{w=1}^{N_h} \Big( T_{\text{comp}}^{(w)} + T_{\text{mem}}^{(w)} + T_{\text{sync}}^{(w)} \Big)
$$

where:

- $T_{\text{comp}}^{(w)} = N_a \cdot M \cdot C_{\text{key}}$ (cycles for key generation + hashing)
- $T_{\text{mem}}^{(w)} = N_a \cdot M \cdot \big( p_{\text{miss}} \cdot L_{\text{miss}} + (1-p_{\text{miss}}) \cdot L_{\text{hit}} \big)$
- $T_{\text{sync}}^{(w)} \approx N_a \cdot C_{\text{atomic}}$ (per‑thread `found` flag checks)

**Cycles per key check ($C_{\text{key}}$):**

$$
C_{\text{key}} = C_{\text{combine}} + C_{\text{serialize}} + C_{\text{SHA256}} + C_{\text{RIPEMD160}} + C_{\text{memcmp}} \approx 2950\text{ cycles}
$$

**Cache miss penalty:**

$$
L_{\text{miss}} \approx 200\text{ cycles},\quad L_{\text{hit}} = 4\text{ cycles}
$$

**Cache miss probability after optimisation:**

$$
p_{\text{miss}} \approx \frac{D_{\text{working set}}}{C_{\text{cache}}} \cdot \alpha,\quad \alpha \in [0.05,\,0.15]
$$

With $D_{\text{working set}} = N_a \cdot |\text{Precomp}|$ and a 16 MB L3 cache, $p_{\text{miss}}$ drops from ~0.6 to ~0.07.

---

## Memory Structures and Alignment

The precomputation table is defined with strict 128-byte alignment (2x 64-byte Cache Lines) to prevent memory fragmentation and splitting:

```c
struct Precomp {
    secp256k1_pubkey const_pub;   // 64 bytes (compressed)
    uint64_t anom_offset;         // 8 bytes
    int ch;                       // 4 bytes
    const char* name;             // 8 bytes
    uint128_t const_value;        // 16 bytes
    char padding[28];             // Pad to 128 bytes total (100 + 28)
} __attribute__((aligned(64)));