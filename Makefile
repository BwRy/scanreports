# vim: noexpandtab, tabstop=4
#

ifndef PREFIX
	PREFIX:=/usr/local
endif
VERSION= $(shell awk -F\' '/^VERSION/ {print $$2}' setup.py)

all:

clean:
	@echo "Cleanup python build directories"
	rm -rf build dist *.egg-info */*.egg-info *.pyc */*.pyc

package: clean
	rm -rf scanreports-$(VERSION)
	mkdir -p scanreports-$(VERSION)
	for f in Makefile README.txt bin scanreports setup.py;do cp -R $$f scanreports-$(VERSION)/$$d;done
	tar -zcf ../scanreports-$(VERSION).tar.gz --exclude=.git --exclude=.gitignore --exclude=*.swp --exclude=*.pyc scanreports-$(VERSION) 

modules:
	python setup.py build

install_modules: modules
	@echo "Installing python modules"
	@python setup.py install

install: install_modules 
	@echo "Installing scripts to $(PREFIX)/bin/"
	@install -m 0755 -d $(PREFIX)/bin
	@for f in bin/*; do \
		echo " $(PREFIX)/$$f";install -m 755 $$f $(PREFIX)/bin/; \
	done;

