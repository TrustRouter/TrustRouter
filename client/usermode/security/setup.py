from distutils.core import setup, Extension
setup(name="security", version="1.0", ext_modules=[Extension(
        "security",
        libraries=['crypto'],
        library_dirs=['./lib/x64', './lib/ia32'],
        include_dirs=['./include'],
        sources=["security.c"],
        define_macros=[("DEBUG", None)],
      )])
print("\n\nRemember to copy the compiled library!\n\n")