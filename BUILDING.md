libfte Build Instructions
===========================

Ubuntu/Debian
-------------

Install the following packages.
```
sudo apt-get install python-dev python-pip libgmp-dev git
sudo pip install crypto
```

Then, clone and build libfte.
```
git clone https://github.com/kpdyer/libfte.git
cd libfte
sudo python setup.py install
```

OSX
---

Install homebrew [1], if you don't have it already.

```
ruby -e "$(curl -fsSL https://raw.github.com/Homebrew/homebrew/go/install)"
```

Install the following packages.
```
brew install --build-from-source python gmp git
sudo pip install --upgrade crypto
```

Then, clone and build libfte.
```
git clone https://github.com/kpdyer/libfte.git
cd libfte
sudo python setup.py install
```

Note: if on OSX 10.9, you may experience a ```clang: warning: argument unused during compilation: '-mno-fused-madd'``` error. This can be resolved by setting the following evnironmental variables:

```
export CFLAGS=-Qunused-arguments
export CPPFLAGS=-Qunused-arguments
```

Windows
-------

If you must build libfte on Windows, please see [2] for guidance.


### References

* [1] http://brew.sh/
* [2] https://github.com/kpdyer/libfte-builder/blob/master/build/windows-i386/build_libfte.sh
