
PLUGINS = $(shell find  -maxdepth 1 -type d | grep -e '^./bmx_' )

%:
	set -e; for d in $(PLUGINS); do $(MAKE) -C $$d $@; done
