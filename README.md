# xorv
Help prevent static analysis on strings and values using buffer size randomization and double-xor. Inspired by xorstr.

# How to use
For strings: _xs(String)
For values: _xv(Value)
To clear a string off of stack: xorv::clear(String) or xorv::clear_encrypt(String)

# Downfalls
Unfortunately, compilation time is exceedingly slow due to the overall setup of the project. Optimization may be necessary for a large scale implementation. Removing the mm256 intrinsics makes code generation much faster.
Support for floating-point values only exists with C++17 or higher. Other than that, the code has been tested working on C++14 (without using floating-point encryption) inside a library with no issues.

# Benefits
You can modify the decryption algorithm to be anything you want. For example, something that connects to the internet to download a decryption key, making static analysis impossible.
