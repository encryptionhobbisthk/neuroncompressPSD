
# Benchmarks

| Data Type | Ratio (Lossy) | Ratio (Lossless) | Time | Memory |
|----------|---------------|------------------|------|--------|
| Text (enwik9) | 92-93% (12.3:1) | 88% (8.3:1) | ~0.5-0.8 min | ~70-100 MB |
| Audio | 83% | 75-80% | ~0.1-0.3s | ~70 MB |
| Image | 98.5-98.7% | 96.7% | ~0.05s | ~80 MB |
| Video | 99.3-99.5% | 97.8% | ~1-2s | ~100 MB |

**Comparison**: Beats cmix (9.3:1), PAQ8 (8:1), LMCompress (6.7:1) on text; ~30-50% better on multimedia.
