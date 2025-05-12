from setuptools import setup, find_packages

setup(
    name='secure-file-storage-system',
    version='1.0.0',
    packages=find_packages(),
    python_requires='>=3.8,<3.9',
    install_requires=[
        'requests>=2.31.0',
        'cryptography>=41.0.0',
        'python-dotenv>=1.0.0',
        'click>=8.0.0'
    ],
    entry_points={
        'console_scripts': [
            'sfss=src.sfss_cli:cli'
        ],
    }
)
