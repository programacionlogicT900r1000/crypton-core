#include "elliptic_search.hpp"

int main() {
    SearchConfig cfg;
    cfg.num_threads = 8;   // adjust to your CPU
    OptimizedEllipticSearch search(cfg);
    search.run();
    return 0;
}