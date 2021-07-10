MBEDTLS=/ssw/projects/pandora/belgrade/mbedtls
CFLAGS+= -I${MBEDTLS}/include

LDFLAGS+=-L${MBEDTLS}/library -lmbedtls -lmbedx509 -lmbedcrypto

all: example1

example1: example1.c
	${CC} ${CFLAGS} example1.c   -o example1 ${LDFLAGS}
