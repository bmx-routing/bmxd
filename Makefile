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


CFLAGS =	-Wall -O2 -g -pg  -DDEBUG_MALLOC -DMEMORY_USAGE -DPROFILE_DATA 
# -DEXT_DBG # WARNING: this one eats your CPU. Do NOT use it for embedded devices!

LDFLAGS =	-lpthread -static -g -pg



CFLAGS_MIPS =	-Wall -O2 -g3 -DDEBUG_MALLOC -DMEMORY_USAGE -DPROFILE_DATA -DREVISION_VERSION=$(REVISION_VERSION)
LDFLAGS_MIPS =	-lpthread

UNAME=		$(shell uname)
POSIX_C=	posix/init.c posix/posix.c posix/tunnel.c

ifeq ($(UNAME),Linux)
OS_C=	 linux/route.c linux/tun.c  $(POSIX_C)
endif

SBINDIR =       $(INSTALL_PREFIX)/usr/sbin

LOG_BRANCH= trunk/batman-experimental

SRC_FILES= "\(\.c\)\|\(\.h\)\|\(Makefile\)\|\(INSTALL\)\|\(LIESMICH\)\|\(README\)\|\(THANKS\)\|\(./posix\)\|\(./linux\)\|\(./man\)\|\(./doc\)"

SRC_C= batman.c originator.c dispatch.c list-batman.c allocate.c hash.c profile.c control.c metrics.c $(OS_C)
SRC_H= batman.h originator.h dispatch.h list-batman.h allocate.h hash.h profile.h control.h metrics.h vis-types.h os.h

PACKAGE_NAME=	batmand-exp
BINARY_NAME=	batmand

#PACKAGE_NAME=	bmx
#BINARY_NAME=	bmxd


SOURCE_VERSION_HEADER= batman.h

IPKG_DEPENDS=		"kmod-tun libpthread"


all:	$(BINARY_NAME)

$(BINARY_NAME):	$(SRC_C) $(SRC_H) Makefile
	$(CC) $(CFLAGS) -o $@ $(SRC_C) $(LDFLAGS)


install:	all
		mkdir -p $(SBINDIR)
		install -m 0755 $(BINARY_NAME) $(SBINDIR)/bmxd


clean:
		rm -f $(BINARY_NAME) *.o

clean-all:
		rm -rf $(PACKAGE_NAME)_* dl/*