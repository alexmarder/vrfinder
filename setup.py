from Cython.Distutils import build_ext
from setuptools import setup, find_packages
from setuptools.extension import Extension
from Cython.Build import cythonize


extensions_names = {
    'vrfinder.finder': ['vrfinder/finder.pyx'],
}

extensions = [Extension(k, v) for k, v in extensions_names.items()]
package_data = {k: ['*.pxd'] for k in extensions_names}

setup(
    name="vrfinder",
    version='0.0.1',
    packages=find_packages(),
    cmdclass={'build_ext': build_ext},
    ext_modules=cythonize(
        extensions,
        compiler_directives={
            'language_level': '3',
        },
        annotate=True
    ),
    zip_safe=False,
    package_data=package_data,
    include_package_data=True
)
