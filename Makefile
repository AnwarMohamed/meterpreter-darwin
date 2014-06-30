all: osx-lib ios-lib

osx-lib:
	make -C osx

ios-lib:
	make -C ios

clean:
	$(MAKE) clean -C osx
	$(MAKE) clean -C ios

install:
	$(MAKE) install -C osx
	$(MAKE) install -C ios
