# setup.py
from setuptools import setup
from Cython.Build import cythonize
import numpy

setup(
    name="vedic_ops",
    ext_modules=cythonize("vedic_ops.pyx", compiler_directives={'language_level': "3"}),
    include_dirs=[numpy.get_include()],
)
