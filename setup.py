from setuptools import setup, find_packages

setup(
    name="rapids",
    version="0.1",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "pandas>=1.3.0",
        "numpy>=1.20.0",
        "matplotlib>=3.4.0",
        "seaborn>=0.11.0",
        "sqlalchemy>=1.4.0",
        "psycopg2-binary>=2.9.0"
    ],
    python_requires=">=3.8",
)
