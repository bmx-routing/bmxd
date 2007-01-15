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

# export PATH=$PATH:/usr/src/openWrt/build/trunk/staging_dir_mipsel/bin/  to ~/.bash_profile

MCC =		/usr/src/openWrt/build/trunk/staging_dir_mipsel/bin/mipsel-linux-uclibc-gcc
MSTRIP =	/usr/src/openWrt/build/trunk/staging_dir_mipsel/bin/mipsel-linux-uclibc-strip

MLDFLAGS =  -lpthread
MCFLAGS =	-Wall -O0 -g3

UNAME=$(shell uname)

ifeq ($(UNAME),Linux)
#OS_OBJ=	posix-specific.o posix.o linux.o allocate.o

#MOS_OBJ=	posix-m32.o linux-m32.o allocate-m32.o batman-m32.o

OS_SRC_H=		bmex.h list.h os.h allocate.h
OS_SRC_C=		bmex.c posix-specific.c posix.c linux.c allocate.c 
endif

all:		bmex bmex-x86dp bmex-m32s bmex-m32sp bmex-m32d


bmex:	$(OS_SRC_C) $(OS_SRC_H) Makefile 
		$(CC) $(CFLAGS) -o $@ $(OS_SRC_C) $(LDFLAGS)

bmex-x86dp:	bmex
			strip -o $@ bmex


bmex-m32d:	$(OS_SRC_C) $(OS_SRC_H) Makefile
			$(MCC) $(MCFLAGS) -o $@ $(OS_SRC_C) $(MLDFLAGS)

bmex-m32dp:	bmex-m32d
			$(MSTRIP) -o $@ bmex-m32d
			
bmex-m32s:	$(OS_SRC_C) $(OS_SRC_H) Makefile
			$(MCC) $(MCFLAGS) -o $@ $(OS_SRC_C) -static $(MLDFLAGS)

bmex-m32sp:	bmex-m32s
			$(MSTRIP) -o $@ bmex-m32s

		
clean:
		rm -f bmex bmex-* *.o *~



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
