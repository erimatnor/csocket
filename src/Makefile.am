SUBDIRS = . test
lib_LTLIBRARIES = libcsocket.la
libcsocket_la_SOURCES = \
	socket.c 

if OS_MACOSX
libcsocket_la_CFLAGS = -Wno-deprecated-declarations
endif

libcsocket_la_CPPFLAGS = -I$(top_srcdir)/include
libcsocket_la_includedir = $(includedir)/csocket
libcsocket_la_include_HEADERS = \
	$(top_srcdir)/include/csocket/csocket.h \
	$(top_srcdir)/include/csocket/socket.h \
	$(top_srcdir)/include/csocket/ssl_socket.h


if HAVE_OPENSSL
libcsocket_la_SOURCES += \
	ssl_socket.c
libcsocket_la_CPPFLAGS += \
	$(OPENSSL_INCLUDES)
libcsocket_la_LDFLAGS = \
	$(OPENSSL_LDFLAGS) $(OPENSSL_LIBS)
endif

clean-local:
	rm -f *~
