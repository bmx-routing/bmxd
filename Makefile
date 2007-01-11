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

CC =		gcc
CFLAGS =	-Wall -O0 -g3
LDFLAGS =	-lpthread

# export PATH=$PATH:/usr/src/openWrt/build/trunk/openwrt/staging_dir_mipsel/bin/  to ~/.bash_profile

MCC =		/usr/src/openWrt/build/trunk/staging_dir_mipsel/bin/mipsel-linux-uclibc-gcc
MLDFLAGS =	-static -lpthread
MCFLAGS =	-Wall -O0 -g3 -c -static

UNAME=$(shell uname)

ifeq ($(UNAME),Linux)
#OS_OBJ=	posix.o linux.o allocate.o
OS_OBJ=	
OS_SRC=		bmex.c bmex.h list.h Makefile
endif

all:		bmex-x86 bmex-m32

bmex-x86:	bmex.o $(OS_OBJ)
		$(CC)  $(LDFLAGS) -o $@ bmex.o $(OS_OBJ)


bmex-m32.o:	$(OS_SRC)
		$(MCC) $(MCFLAGS) -o $@ bmex.c

bmex-m32:	bmex-m32.o $(OS_OBJ)
		$(MCC) $(MLDFLAGS) -o $@ bmex-m32.o $(OS_OBJ) 

clean:
		rm -f bmex-m32 bmex-x86 *.o *~



install: 	
#		scp bmex-m32 root@ng1e:/tmp/
		scp bmex-m32 root@ng2e:/tmp/
		scp bmex-m32 root@ng3e:/tmp/
#		scp bmex-m32 root@ng4e:/tmp/
#		scp bmex-m32 root@ng5e:/tmp/
#		scp bmex-m32 root@ng6e:/tmp/

install-ng1: 	
		scp bmex-m32 root@ng1e:/tmp/

install-ng2: 	
		scp bmex-m32 root@ng2e:/tmp/

install-ng3: 	
		scp bmex-m32 root@ng3e:/tmp/

install-ng4: 	
		scp bmex-m32 root@ng4e:/tmp/

install-ng5: 	
		scp bmex-m32 root@ng5e:/tmp/

install-ng6: 	
		scp bmex-m32 root@ng6e:/tmp/
