# Automatically figure out what we're doing

ifneq ($(CROSS_COMPILE),1)
CROSS_COMPILE=0
PLATFORM_UNAME=$(shell uname)
PLATFORM=$(shell echo $(PLATFORM_UNAME) | tr A-Z a-z)
ifneq (,$(findstring cygwin,$(PLATFORM)))
PLATFORM='windows'
WINDOWS_BUILD=1
endif
ARCH=$(shell arch)
endif

VERSION=$(shell cat fte/VERSION)
FTEPROXY_RELEASE=$(VERSION)-$(PLATFORM)-$(ARCH)
THIRD_PARTY_DIR=thirdparty
CDFA_BINARY=fte/cDFA.so

ifeq ($(PYTHON),)
PYTHON="python"
endif

ifeq ($(WINDOWS_BUILD),1)
CDFA_BINARY=fte/cDFA.pyd
endif

default: $(CDFA_BINARY)

dist-deb:
	@rm -rfv debian/libfte
	DEB_CPPFLAGS_SET="-fPIC" dpkg-buildpackage -b -us -uc
	mkdir -p dist
	cp ../*deb dist/
	cp ../*changes dist/
	
clean:
	@rm -rfv fte.egg-info
	@rm -rvf build
	@rm -rvf dist
	@rm -vf fte/*.so
	@rm -vf fte/*.pyd
	@rm -vf *.pyc
	@rm -vf */*.pyc
	@rm -vf */*/*.pyc
	@rm -rvf debian/python-fte
	

test:
	$(PYTHON) setup.py test

$(CDFA_BINARY):
ifeq ($(WINDOWS_BUILD),1)
	$(PYTHON) setup.py build_ext -c mingw32
else
	$(PYTHON) setup.py build_ext
endif

install:
	$(PYTHON) setup.py install --root=$(DESTDIR) --install-layout=deb
