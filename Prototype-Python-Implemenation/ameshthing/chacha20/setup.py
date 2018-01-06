from distutils.core import setup, Extension

# To build: python3 setup.py build_ext --inplace

chachamod = Extension('_chacha20',
                      sources = ['_chacha20.cpp'])

setup (
       name = 'ChaCha20Box',
       version = '0.2',
       description = 'A python interface for using ChaCha20 for symmetric encryption with C++ at the core.',
       ext_modules = [chachamod]
    )
