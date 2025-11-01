[app]
title = CompressionProgram
package.name = compressionprogram
package.domain = org.example

source.dir = .
source.include_exts = py,png,jpg,kv,atlas,pyx,so,pyd

version = 0.1
requirements = python3,kivy,numpy,scipy,lzma,zlib,requests,base64,lz4,zopfli,brotli,webp,pillow,ffmpeg-python,pyflac,zstandard,cython,joblib,imageio

orientation = portrait
osx.python_version = 3
osx.kivy_version = 2.1.0

[buildozer]
log_level = 2
