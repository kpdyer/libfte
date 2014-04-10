# This file is part of libfte.
#
# libfte is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation,either version 3 of the License,or
# (at your option) any later version.
#
# libfte is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with libfte.  If not,see <http://www.gnu.org/licenses/>.


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
ifeq ($(WINDOWS_BUILD),1)
RE2_DIR=$(THIRD_PARTY_DIR)/re2-win32
else
RE2_DIR=$(THIRD_PARTY_DIR)/re2
endif
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
	@cd $(RE2_DIR) && make clean
	

test:
	$(PYTHON) setup.py test


libre2.a: $(THIRD_PARTY_DIR)/re2/obj/libre2.a
$(CDFA_BINARY): $(THIRD_PARTY_DIR)/re2/obj/libre2.a
ifeq ($(WINDOWS_BUILD),1)
	$(PYTHON) setup.py build_ext -c mingw32
else
	$(PYTHON) setup.py build_ext
endif

$(THIRD_PARTY_DIR)/re2/obj/libre2.a:
	cd $(RE2_DIR) && $(MAKE) obj/libre2.a


install:
	$(PYTHON) setup.py install --root=$(DESTDIR) --install-layout=deb
