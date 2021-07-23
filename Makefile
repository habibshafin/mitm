all:
	$(MAKE) -C spoof/
	$(MAKE) -C sniff/

clean:
	$(MAKE) clean -C spoof/
	$(MAKE) clean -C sniff/
