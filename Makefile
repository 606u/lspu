
PROG=	lspu
MAN=	
SRCS=	lspu.c

CFLAGS += -Wall -Wextra
CFLAGS += -g -O0
LDFLAGS += -g

LDADD+=	-lprocstat
DPADD+=	${LIBUTIL} ${LIBPROCSTAT} ${LIBKVM}

.include <bsd.prog.mk>

test1: all
	./lspu /usr/jails/basejail/lib/libutil.so.9 /lib/libutil.so.9

test2: all
	./lspu /lib/libcam.so.6

test3: all
	./lspu /usr/sbin/sshd
