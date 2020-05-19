build: .FORCE
	python setup.py build

doc: .FORCE
	PYTHONPATH=. $(MAKE) -C doc html

install: build .FORCE
	python setup.py install

test:
	PYTHONPATH=. bin/classified -c testdata/classified.conf -v testdata/

.FORCE:
