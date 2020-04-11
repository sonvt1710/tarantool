#include <iconv.h>

iconv_t
tnt_iconv_open(const char *tocode, const char *fromcode)
{
        return iconv_open(tocode, fromcode);
}

int
tnt_iconv_close(iconv_t cd)
{
        return iconv_close(cd);
}

size_t
tnt_iconv(iconv_t cd, char **inbuf, size_t *inbytesleft,
          char **outbuf, size_t *outbytesleft)
{
        return iconv(cd, inbuf, inbytesleft,
                     outbuf, outbytesleft);
}

void **
tarantool_lua_tnt_iconv_export_syms(void)
{
	static void *syms[] = {
		(void *)tnt_iconv,
		(void *)tnt_iconv_close,
		(void *)tnt_iconv_open,
	};
	return syms;
}
