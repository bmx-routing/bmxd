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


# CC =		gcc

CFLAGS =	-Wall -O1 -g -pg

#-DDEBUG_MALLOC -DMEMORY_USAGE -DPROFILE_DATA

LDFLAGS =	-lpthread -static -g -pg


#STRIP=			strip



CFLAGS_MIPS =	-Wall -O1 -g3 -DDEBUG_MALLOC -DMEMORY_USAGE -DPROFILE_DATA -DREVISION_VERSION=$(REVISION_VERSION)
LDFLAGS_MIPS =	-lpthread

UNAME=		$(shell uname)
POSIX_C=	posix/init.c posix/posix.c posix/tunnel.c posix/unix_socket.c

ifeq ($(UNAME),Linux)
OS_C=	 linux/route.c linux/tun.c linux/kernel.c $(POSIX_C)
endif

ifeq ($(UNAME),Darwin)
OS_C=	bsd/route.c bsd/tun.c bsd/kernel.c bsd/compat.c $(POSIX_C)
endif

ifeq ($(UNAME),FreeBSD)
OS_C=	bsd/route.c bsd/tun.c bsd/kernel.c bsd/compat.c $(POSIX_C)
endif

ifeq ($(UNAME),OpenBSD)
OS_C=	bsd/route.c bsd/tun.c bsd/kernel.c bsd/compat.c $(POSIX_C)
endif

LOG_BRANCH= trunk/batman-experimental

SRC_FILES= "\(\.c\)\|\(\.h\)\|\(Makefile\)\|\(INSTALL\)\|\(LIESMICH\)\|\(README\)\|\(THANKS\)\|\(Doxyfile\)\|\(./posix\)\|\(./linux\)\|\(./bsd\)\|\(./man\)\|\(./doc\)"

SRC_C= batman.c originator.c schedule.c list-batman.c allocate.c bitarray.c hash.c profile.c $(OS_C)
SRC_H= batman.h originator.h schedule.h list-batman.h os.h allocate.h bitarray.h hash.h profile.h vis-types.h

PACKAGE_NAME=	batmand-exp

BINARY_NAME=	batmand
SOURCE_VERSION_HEADER= batman.h

IPKG_DEPENDS=		"kmod-tun libpthread"


all:	$(BINARY_NAME)

$(BINARY_NAME):	$(SRC_C) $(SRC_H) Makefile
	$(CC) $(CFLAGS) -o $@ $(SRC_C) $(LDFLAGS)

install:	all
	install -m 755 $(BINARY_NAME) $(INSTALL_DIR)/bin
	$(STRIP) $(INSTALL_DIR)/bin/$(BINARY_NAME)

clean:
		rm -f $(BINARY_NAME) *.o

clean-all:
		rm -rf $(PACKAGE_NAME)_* dl/*