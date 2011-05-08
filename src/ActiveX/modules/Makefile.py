
SUBDIRS=hcalert honeyjs libemu
INSTHOME=../..

PYTHON=python

ifneq ($(PHONEYC_PYTHON),)
        PYTHON:= $(PHONEYC_PYTHON)
endif


all:compile

compile:
	@for i in $(SUBDIRS); do \
	echo "make all in $$i..."; \
	(cd $$i; ${PYTHON} setup.py build); done

install:
	@for i in $(SUBDIRS); do \
	echo "install all in $$i..."; \
	(cd $$i; PYTHONPATH=../../lib/python ${PYTHON} setup.py install --home=$(INSTHOME)); done

clean:
	@for i in $(SUBDIRS); do \
	echo "install all in $$i..."; \
	(cd $$i; ${PYTHON} setup.py clean); done

