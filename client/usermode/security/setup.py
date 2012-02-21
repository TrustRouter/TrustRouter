import platform
from distutils.core import setup, Extension


if platform.system() == "Darwin":
	lib_dirs = ['./lib/MacOS/x64', './lib/MacOS/ia32']
# TODO: other OSs

setup(name="security", version="1.0", ext_modules=[Extension(
        "security",
        libraries=['crypto'],
        library_dirs=lib_dirs,
        include_dirs=['./include'],
        sources=["security.c"],
        define_macros=[("DEBUG", None)],
      )])
print("\n\nRemember to copy the compiled library!\n\n")