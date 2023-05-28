AM_CPPFLAGS = \
	-DTEST_SRCDIR=\"@srcdir@\" \
	-I$(top_srcdir)/src/libsodium/include \
	-I$(top_srcdir)/src/libsodium/include/sodium \
	-I$(top_builddir)/src/libsodium/include \
	-I$(top_builddir)/src/libsodium/include/sodium \
	-I$(top_srcdir)/test/quirks

AM_LDFLAGS = @TEST_LDFLAGS@

TESTS_TARGETS = \
    speed_sodium

check_PROGRAMS = $(TESTS_TARGETS)

TESTS = $(TESTS_TARGETS)

TESTS_LDADD = \
	${top_builddir}/src/libsodium/libsodium.la

speed_sodium_SOURCE                 = speed.h speed_sodium.c
speed_sodium_LDADD                  = $(TESTS_LDADD)

verify: check

@VALGRIND_CHECK_RULES@