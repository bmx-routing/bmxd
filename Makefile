#
# Copyright (C) 2006 BATMAN contributors
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of version 2 of the GNU General Public
# License as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA
#

REVISION =	$(shell if [ -d .svn ]; then which svn > /dev/null && which sed > /dev/null && which awk > /dev/null && { svn info | grep "Rev:" | sed -e '1p' -n | awk '{print $$4}';} fi )
REVISION_VERSION =	\"\ rv$(REVISION)\"


CFLAGS +=	 -pedantic -Wall -W -Wno-unused-parameter -O1 -g3 -std=gnu99 -I./ -DREVISION_VERSION=$(REVISION_VERSION) -DDEBUG_MALLOC -DMEMORY_USAGE 

# Recommended defines and approximate binary sizes with gcc-x86
# -static
# -pedantic -Wall -W -Wno-unused-parameter -O1 -g3 -std=gnu99
# -pg  # "-pg" with openWrt toolchain results in "gcrt1.o: No such file" ?!
#

# compared to -O1 stripped:
# -Os								- ~29k
#	
# -DDEBUG_MALLOC  						+ ~0k
# -DMEMORY_USAGE 						+ ~1k
# -DPROFILE_DATA	(some realtime profiling)		+ ~3k

# optional defines (you may disable these features if you dont need it):
# -DNOTRAILER							- ~3K
# -DNODEBUGALL							- ~13k
#
# -DNOTUNNEL  		(only affects this node)		- ~23k
# -DNOSRV  		(only affects this node)		- ~3k
# -DNOVIS  		(only affects this node)		- ~2k

# -DNODEPRECATED	(for backward compatibility)		- ~2k

# experimental or advanced defines (please dont touch):
# -DNOHNA		(affects all nodes in network)		- ~6k
# -DNOPARANOIA		(makes bug-hunting impossible)		- ~2k
# -DEXTDEBUG		(this eats your cpu)			+ ~0k
# -DTESTDEBUG		(testing syntax of __VA_ARGS__ dbg...() macros)
# -DWITHUNUSED		(includes yet unused stuff)

EXTRA_CFLAGS +=

LDFLAGS +=	-Wl,-export-dynamic -ldl -g3
# -static
# -pg


UNAME=		$(shell uname)
POSIX_C=	posix/posix.c posix/tunnel.c

ifeq ($(UNAME),Linux)
OS_C=	 linux/route.c  $(POSIX_C)
endif

SBINDIR =       $(INSTALL_PREFIX)/usr/sbin

LOG_BRANCH= trunk/batman-experimental

SRC_FILES= "\(\.c\)\|\(\.h\)\|\(Makefile\)\|\(INSTALL\)\|\(LIESMICH\)\|\(README\)\|\(THANKS\)\|\(./posix\)\|\(./linux\)\|\(./man\)\|\(./doc\)"

SRC_C= batman.c originator.c hna.c schedule.c plugin.c list-batman.c allocate.c hash.c profile.c control.c metrics.c $(OS_C)
SRC_H= batman.h originator.h hna.h schedule.h plugin.h list-batman.h allocate.h hash.h profile.h control.h metrics.h vis-types.h os.h
OBJS=  $(SRC_C:.c=.o)

#PACKAGE_NAME=	batmand-exp
#BINARY_NAME=	batmand

PACKAGE_NAME=	bmxd
BINARY_NAME=	bmxd



SOURCE_VERSION_HEADER= batman.h


BAT_VERSION=    $(shell grep "^\#define SOURCE_VERSION " $(SOURCE_VERSION_HEADER) | sed -e '1p' -n | awk -F '"' '{print $$2}' | awk '{print $$1}')
FILE_NAME=      $(PACKAGE_NAME)_$(BAT_VERSION)-rv$(REVISION)_$@

NOW=		$(shell date +%Y%m%d%H%M)-$(REVISION)

IPKG_DEPENDS=	"kmod-tun"

SNAPSHOT_DIR=	../bmx-snapshots

all:	
	$(MAKE) $(BINARY_NAME)
	$(MAKE) -C lib $@
	

$(BINARY_NAME):	$(OBJS) Makefile
	$(CC)  $(OBJS) -o $@  $(LDFLAGS) $(EXTRA_LDFLAGS)

%.o:	%.c %.h Makefile $(SRC_H)
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -c $< -o $@

%.o:	%.c Makefile $(SRC_H)
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -c $< -o $@


install:	all
	mkdir -p $(SBINDIR)
	install -m 0755 $(BINARY_NAME) $(SBINDIR)
	$(MAKE) -C lib install
	
clean:
	rm -f $(BINARY_NAME) *.o posix/*.o linux/*.o
	$(MAKE) -C lib clean

