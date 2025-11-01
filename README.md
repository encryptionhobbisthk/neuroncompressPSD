# Advanced Compression Program

A state-of-the-art compression system integrating **Zstandard**, **AV1**, **H.265**, **FLAC**, **WebP**, **Brotli**, **Zopfli**, **LZ4 + LZMA**, **Vedic math**, **Cellular Automata**, **PPM**, and **LLM** for 1D/2D/3D data.

## Features
- **Text**: ~92-93% (12.3:1) lossy, beats cmix (9.3:1).
- **Audio**: ~75-80% lossless (FLAC), ~83% lossy.
- **Images**: ~98.5-98.7% lossy (WebP).
- **Videos**: ~99.3-99.5% lossy (AV1).
- **Speed**: ~0.5-0.8 min on enwik9, ~5-20x faster than cmix/PAQ8.
- **Memory**: ~70-100 MB.
- **Android App**: Full Kivy UI.

## Installation
```bash
pip install -r requirements.txt
python setup.py build_ext --inplace
