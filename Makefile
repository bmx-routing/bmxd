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
CFLAGS =	-Wall -O0 -g3 -pg 
LDFLAGS =	-pg

all:		bmex bmex-mips


bmex:		bmex.o


bmex.o: 	bmex.c bmex.h Makefile
		gcc -static -pg -Wall -O0 -g3 -o bmex.o -c bmex.c

#		export PATH=$PATH:/usr/src/openWrt/build/buildroot-ng/openwrt/staging_dir_mipsel/bin/ # to ~/.bash_profile

bmex-mips:	bmex.c bmex.h  Makefile
		mipsel-linux-uclibc-gcc -static -Wall -O0 -g3 -Os -s bmex.c -o bmex-mips


install: 	
#		scp bmex-mips root@ng1e:/tmp/
		scp bmex-mips root@ng2e:/tmp/
		scp bmex-mips root@ng3e:/tmp/
#		scp bmex-mips root@ng4e:/tmp/
#		scp bmex-mips root@ng5e:/tmp/
#		scp bmex-mips root@ng6e:/tmp/

install-ng1: 	
		scp bmex-mips root@ng1e:/tmp/

install-ng2: 	
#		ssh root@ng2e "killall bmex-mips"
		scp bmex-mips root@ng2e:/tmp/

install-ng3: 	
		scp bmex-mips root@ng3e:/tmp/

install-ng4: 	
		scp bmex-mips root@ng4e:/tmp/

install-ng5: 	
		scp bmex-mips root@ng5e:/tmp/

install-ng6: 	
		scp bmex-mips root@ng6e:/tmp/


#bmex:		bmex.o linux.o

clean:
		rm -f bmex bmex-mips *.o *~
