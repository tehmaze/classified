build: .FORCE
	uv build

doc: .FORCE
	PYTHONPATH=. $(MAKE) -C doc html

install: .FORCE
	uv sync

test:
	uv run bin/classified -c testdata/classified.conf -v testdata/

.FORCE:
