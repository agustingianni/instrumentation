all:
	$(MAKE) -C common
	$(MAKE) -C CodeCoverage
	$(MAKE) -C Recoverer
	$(MAKE) -C Resolver
	# $(MAKE) -C Pinnacle

clean:
	$(MAKE) -C common clean
	$(MAKE) -C CodeCoverage clean
	$(MAKE) -C Recoverer clean
	$(MAKE) -C Resolver clean
	# $(MAKE) -C Pinnacle clean

