from setuptools import setup, find_packages

setup(
    name="pysafescan",
    version="0.1.0",
    author="Your Team Name",
    author_email="your.email@example.com",
    description="Python code security scanner with DeepSeek and Gemini LLM",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/PySafeScan",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
    ],
    python_requires=">=3.9",
    install_requires=[
        # 暂时为空，后面逐步添加
    ],
    extras_require={
        "dev": ["pytest", "black", "flake8"],
    },
    entry_points={
        "console_scripts": [
            "pysafescan=cli:main",
        ],
    },
)
