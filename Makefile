MBEDTLS=/ssw/projects/pandora/belgrade/mbedtls
CFLAGS+= -I${MBEDTLS}/include

LDFLAGS+=-L${MBEDTLS}/library -lmbedtls -lmbedx509 -lmbedcrypto

all: example1
