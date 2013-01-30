build: .FORCE
	python setup.py build

install: build .FORCE
	python setup.py install

test:
	PYTHONPATH=. bin/classified -c classified.conf testdata/

.FORCE:
