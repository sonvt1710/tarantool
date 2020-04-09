/*
 * Copyright 2010-2020, Tarantool AUTHORS, please see AUTHORS file.
 *
 * Redistribution and use in source and binary forms, with or
 * without modification, are permitted provided that the following
 * conditions are met:
 *
 * 1. Redistributions of source code must retain the above
 *    copyright notice, this list of conditions and the
 *    following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials
 *    provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY <COPYRIGHT HOLDER> ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * <COPYRIGHT HOLDER> OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include "box/lua/mp_error.h"
#include "box/error.h"
#include "mpstream.h"
#include "msgpuck.h"
#include "mp_extension_types.h"

enum mp_error_details {
	MP_ERROR_DET_TYPE,
	MP_ERROR_DET_FILE,
	MP_ERROR_DET_LINE,
	MP_ERROR_DET_REASON,
	MP_ERROR_DET_ERRNO,
	MP_ERROR_DET_CODE,
	MP_ERROR_DET_BACKTRACE,
	MP_ERROR_DET_CUSTOM_TYPE,
	MP_ERROR_DET_AD_OBJ_TYPE,
	MP_ERROR_DET_AD_OBJ_NAME,
	MP_ERROR_DET_AD_ACCESS_TYPE
};

enum mp_error_types {
	MP_ERROR_TYPE_UNKNOWN,
	MP_ERROR_TYPE_CLIENT,
	MP_ERROR_TYPE_CUSTOM,
	MP_ERROR_TYPE_ACCESS_DENIED,
	MP_ERROR_TYPE_XLOG,
	MP_ERROR_TYPE_XLOG_GAP,
	MP_ERROR_TyPE_SYSTEM,
	MP_ERROR_TyPE_SOCKET,
	MP_ERROR_TyPE_OOM,
	MP_ERROR_TyPE_TIMED_OUT,
	MP_ERROR_TyPE_CHANNEL_IS_CLOSED,
	MP_ERROR_TyPE_FIBER_IS_CANCELLED,
	MP_ERROR_TyPE_LUAJIT,
	MP_ERROR_TyPE_ILLEGAL_PARAMS,
	MP_ERROR_TyPE_COLLATION,
	MP_ERROR_TyPE_SWIM,
	MP_ERROR_TyPE_CRYPTO
};

struct mp_error {
	uint32_t error_code;
	uint8_t error_type;
	uint32_t line;
	uint32_t saved_errno;
	char *file;
	char *backtrace;
	char *reason;
	char *custom_type;
	char *ad_obj_type;
	char *ad_obj_name;
	char *ad_access_type;
};

static void
mp_error_init(struct mp_error *mp_error)
{
	mp_error->error_type = MP_ERROR_TYPE_UNKNOWN;
	mp_error->file = NULL;
	mp_error->backtrace = NULL;
	mp_error->reason = NULL;
	mp_error->custom_type = NULL;
	mp_error->ad_obj_type = NULL;
	mp_error->ad_obj_name = NULL;
	mp_error->ad_access_type = NULL;
}

static void
mp_error_cleanup(struct mp_error *mp_error)
{
	mp_error->error_type = MP_ERROR_TYPE_UNKNOWN;
	free(mp_error->file);
	free(mp_error->backtrace);
	free(mp_error->reason);
	free(mp_error->custom_type);
	free(mp_error->ad_obj_type);
	free(mp_error->ad_obj_name);
	free(mp_error->ad_access_type);
}

static uint8_t
mp_error_type_from_str(const char *type_str)
{
	if (type_str == NULL) {
		return MP_ERROR_TYPE_UNKNOWN;
	} else if (strcmp(type_str, "ClientError") == 0) {
		return MP_ERROR_TYPE_CLIENT;
	} else if (strcmp(type_str, "CustomError") == 0) {
		return MP_ERROR_TYPE_CUSTOM;
	} else if (strcmp(type_str, "AccessDeniedError") == 0) {
		return MP_ERROR_TYPE_ACCESS_DENIED;
	} else if (strcmp(type_str, "XlogError") == 0) {
		return MP_ERROR_TYPE_XLOG;
	} else if (strcmp(type_str, "XlogGapError") == 0) {
		return MP_ERROR_TYPE_XLOG_GAP;
	} else if (strcmp(type_str, "SystemError") == 0) {
		return MP_ERROR_TyPE_SYSTEM;
	} else if (strcmp(type_str, "SocketError") == 0) {
		return MP_ERROR_TyPE_SOCKET;
	} else if (strcmp(type_str, "OutOfMemory") == 0) {
		return MP_ERROR_TyPE_OOM;
	} else if (strcmp(type_str, "TimedOut") == 0) {
		return MP_ERROR_TyPE_TIMED_OUT;
	} else if (strcmp(type_str, "ChannelIsClosed") == 0) {
		return MP_ERROR_TyPE_CHANNEL_IS_CLOSED;
	} else if (strcmp(type_str, "FiberIsCancelled") == 0) {
		return MP_ERROR_TyPE_FIBER_IS_CANCELLED;
	} else if (strcmp(type_str, "LuajitError") == 0) {
		return MP_ERROR_TyPE_LUAJIT;
	} else if (strcmp(type_str, "IllegalParams") == 0) {
		return MP_ERROR_TyPE_ILLEGAL_PARAMS;
	} else if (strcmp(type_str, "CollationError") == 0) {
		return MP_ERROR_TyPE_COLLATION;
	} else if (strcmp(type_str, "SwimError") == 0) {
		return MP_ERROR_TyPE_SWIM;
	} else if (strcmp(type_str, "CryptoError") == 0) {
		return MP_ERROR_TyPE_CRYPTO;
	}

	return MP_ERROR_TYPE_UNKNOWN;
}

void
error_to_mpstream(struct error *error, struct mpstream *stream)
{
	uint8_t err_type = mp_error_type_from_str(box_error_type(error));

	uint32_t errcode;
	const char *custom_type = NULL;
	const char *ad_obj_type = NULL;
	const char *ad_obj_name = NULL;
	const char *ad_access_type = NULL;

	/* Error type, reason, errno, file and line are the necessary fields */
	uint32_t details_num = 5;

	uint32_t data_size = 0;

	data_size += mp_sizeof_uint(MP_ERROR_DET_TYPE);
	data_size += mp_sizeof_uint(err_type);
	data_size += mp_sizeof_uint(MP_ERROR_DET_LINE);
	data_size += mp_sizeof_uint(error->line);
	data_size += mp_sizeof_uint(MP_ERROR_DET_FILE);
	data_size += mp_sizeof_str(strlen(error->file));
	data_size += mp_sizeof_uint(MP_ERROR_DET_REASON);
	data_size += mp_sizeof_str(strlen(error->errmsg));
	data_size += mp_sizeof_uint(MP_ERROR_DET_ERRNO);
	data_size += mp_sizeof_uint(error->saved_errno);

	if (error->lua_traceback) {
		++details_num;
		data_size += mp_sizeof_uint(MP_ERROR_DET_BACKTRACE);
		data_size += mp_sizeof_str(strlen(error->lua_traceback));
	}

	if (err_type == MP_ERROR_TYPE_CLIENT ||
	    err_type == MP_ERROR_TYPE_ACCESS_DENIED ||
	    err_type == MP_ERROR_TYPE_CUSTOM) {
		++details_num;
		errcode = box_error_code(error);
		data_size += mp_sizeof_uint(MP_ERROR_DET_CODE);
		data_size += mp_sizeof_uint(errcode);
		if (err_type == MP_ERROR_TYPE_CUSTOM) {
			++details_num;
			data_size += mp_sizeof_uint(MP_ERROR_DET_CUSTOM_TYPE);
			custom_type = box_custom_error_type(error);
			data_size += mp_sizeof_str(strlen(custom_type));
		} else if (err_type == MP_ERROR_TYPE_ACCESS_DENIED) {
			AccessDeniedError *ad_err = type_cast(AccessDeniedError,
							      error);
			details_num += 3;
			ad_obj_type = ad_err->object_type();
			ad_obj_name = ad_err->object_name();
			ad_access_type = ad_err->access_type();
			data_size += mp_sizeof_uint(MP_ERROR_DET_AD_OBJ_TYPE);
			data_size += mp_sizeof_str(strlen(ad_obj_type));
			data_size += mp_sizeof_uint(MP_ERROR_DET_AD_OBJ_NAME);
			data_size += mp_sizeof_str(strlen(ad_obj_name));
			data_size += mp_sizeof_uint(MP_ERROR_DET_AD_ACCESS_TYPE);
			data_size += mp_sizeof_str(strlen(ad_access_type));
		}
	}

	data_size += mp_sizeof_map(details_num);
	uint32_t data_size_ext = mp_sizeof_ext(data_size);
	char *ptr = mpstream_reserve(stream, data_size_ext);

	char *data = ptr;
	data = mp_encode_extl(data, MP_ERROR, data_size);
	data = mp_encode_map(data, details_num);
	data = mp_encode_uint(data, MP_ERROR_DET_TYPE);
	data = mp_encode_uint(data, err_type);
	data = mp_encode_uint(data, MP_ERROR_DET_LINE);
	data = mp_encode_uint(data, err_type);
	data = mp_encode_uint(data, MP_ERROR_DET_FILE);
	data = mp_encode_str(data, error->file, strlen(error->file));
	data = mp_encode_uint(data, MP_ERROR_DET_REASON);
	data = mp_encode_str(data, error->errmsg, strlen(error->errmsg));
	data = mp_encode_uint(data, MP_ERROR_DET_ERRNO);
	data = mp_encode_uint(data, error->saved_errno);
	if(error->lua_traceback) {
		data = mp_encode_uint(data, MP_ERROR_DET_BACKTRACE);
		data = mp_encode_str(data, error->lua_traceback,
				     strlen(error->lua_traceback));
	}

	if (err_type == MP_ERROR_TYPE_CLIENT ||
	    err_type == MP_ERROR_TYPE_ACCESS_DENIED ||
	    err_type == MP_ERROR_TYPE_CUSTOM) {
		data = mp_encode_uint(data, MP_ERROR_DET_CODE);
		data = mp_encode_uint(data, errcode);
		if (err_type == MP_ERROR_TYPE_CUSTOM) {
			data = mp_encode_uint(data, MP_ERROR_DET_CUSTOM_TYPE);
			data = mp_encode_str(data, custom_type,
					     strlen(custom_type));
		} else if (err_type == MP_ERROR_TYPE_ACCESS_DENIED) {
			data = mp_encode_uint(data, MP_ERROR_DET_AD_OBJ_TYPE);
			data = mp_encode_str(data, ad_obj_type,
					     strlen(ad_obj_type));
			data = mp_encode_uint(data, MP_ERROR_DET_AD_OBJ_NAME);
			data = mp_encode_str(data, ad_obj_name,
					     strlen(ad_obj_name));
			data = mp_encode_uint(data, MP_ERROR_DET_AD_ACCESS_TYPE);
			data = mp_encode_str(data, ad_access_type,
					     strlen(ad_access_type));
		}
	}

	assert(data == ptr + data_size_ext);
	mpstream_advance(stream, data_size_ext);
}

static struct error *
build_error(struct mp_error *mp_error)
{
	struct error *err;
	switch (mp_error->error_type) {
	case MP_ERROR_TYPE_UNKNOWN:
		err = NULL;
		break;
	case MP_ERROR_TYPE_CLIENT:
	{
		ClientError *e = new ClientError(mp_error->file, mp_error->line,
						 ER_UNKNOWN);
		e->m_errcode = mp_error->error_code;
		err = (struct error *)e;
		break;
	}
	case MP_ERROR_TYPE_CUSTOM:
		err = BuildCustomError(mp_error->file, mp_error->line,
				       mp_error->custom_type);
		break;
	case MP_ERROR_TYPE_ACCESS_DENIED:
		err = BuildAccessDeniedError(mp_error->file, mp_error->line,
					     mp_error->ad_access_type,
					     mp_error->ad_obj_type,
					     mp_error->ad_obj_name, "");
		break;
	case MP_ERROR_TYPE_XLOG:
		err = BuildXlogError(mp_error->file, mp_error->line,
				     "%s", mp_error->reason);
		break;
	case MP_ERROR_TYPE_XLOG_GAP:
		err = ReBuildXlogGapError(mp_error->file, mp_error->line,
					  mp_error->reason);
		break;
	case MP_ERROR_TyPE_SYSTEM:
		err = BuildSystemError(mp_error->file, mp_error->line,
				       "%s", mp_error->reason);
		break;
	case MP_ERROR_TyPE_SOCKET:
		err = BuildSocketError(mp_error->file, mp_error->line, "", "");
		error_format_msg(err, "", mp_error->reason);
		break;
	case MP_ERROR_TyPE_OOM:
		err = BuildOutOfMemory(mp_error->file, mp_error->line,
				       0, "", "");
		error_format_msg(err, "%s", mp_error->reason);
		break;
	case MP_ERROR_TyPE_TIMED_OUT:
		err = BuildTimedOut(mp_error->file, mp_error->line);
		break;
	case MP_ERROR_TyPE_CHANNEL_IS_CLOSED:
		err = BuildChannelIsClosed(mp_error->file, mp_error->line);
		break;
	case MP_ERROR_TyPE_FIBER_IS_CANCELLED:
		err = BuildFiberIsCancelled(mp_error->file, mp_error->line);
		break;
	case MP_ERROR_TyPE_LUAJIT:
		err = BuildLuajitError(mp_error->file, mp_error->line,
				       mp_error->reason);
		break;
	case MP_ERROR_TyPE_ILLEGAL_PARAMS:
		err = BuildIllegalParams(mp_error->file, mp_error->line,
					 "%s", mp_error->reason);
		break;
	case MP_ERROR_TyPE_COLLATION:
		err = BuildCollationError(mp_error->file, mp_error->line,
					  "%s", mp_error->reason);
		break;
	case MP_ERROR_TyPE_SWIM:
		err = BuildSwimError(mp_error->file, mp_error->line,
				     "%s", mp_error->reason);
		break;
	case MP_ERROR_TyPE_CRYPTO:
		err = BuildCryptoError(mp_error->file, mp_error->line,
				       "%s", mp_error->reason);
		break;
	default:
		break;
	}

	err->traceback_mode = false;
	err->saved_errno = mp_error->saved_errno;
	error_format_msg(err, "%s", mp_error->reason);

	return err;
}

struct error *
error_unpack(const char **data, uint32_t len)
{
	const char *svp = *data;
	if (mp_typeof(**data) != MP_MAP) {
		diag_set(ClientError, ER_INVALID_MSGPACK,
			 "Invalid MP_ERROR format");
		return NULL;
	}

	struct mp_error mp_err;
	mp_error_init(&mp_err);

	uint32_t map_size = mp_decode_map(data);

	struct error *err = NULL;
	for (uint32_t i = 0; i < map_size; ++i) {
		if (mp_typeof(**data) != MP_UINT) {
			diag_set(ClientError, ER_INVALID_MSGPACK,
				 "Invalid MP_ERROR MsgPack format");
			return NULL;
		}

		uint8_t key = mp_decode_uint(data);
		const char *str;
		uint32_t str_len;
		switch(key) {
		case MP_ERROR_DET_TYPE:
			if (mp_typeof(**data) != MP_UINT)
				goto error;
			mp_err.error_type = mp_decode_uint(data);
			break;
		case MP_ERROR_DET_FILE:
			if (mp_typeof(**data) != MP_STR)
				goto error;
			str = mp_decode_str(data, &str_len);
			mp_err.file = strndup(str, str_len);
			break;
		case MP_ERROR_DET_LINE:
			if (mp_typeof(**data) != MP_UINT)
				goto error;
			mp_err.line = mp_decode_uint(data);
			break;
		case MP_ERROR_DET_REASON:
			if (mp_typeof(**data) != MP_STR)
				goto error;
			str = mp_decode_str(data, &str_len);
			mp_err.reason = strndup(str, str_len);
			break;
		case MP_ERROR_DET_ERRNO:
			if (mp_typeof(**data) != MP_UINT)
				goto error;
			mp_err.saved_errno = mp_decode_uint(data);
			break;
		case MP_ERROR_DET_CODE:
			if (mp_typeof(**data) != MP_UINT)
				goto error;
			mp_err.error_code = mp_decode_uint(data);
			break;
		case MP_ERROR_DET_BACKTRACE:
			if (mp_typeof(**data) != MP_STR)
				goto error;
			str = mp_decode_str(data, &str_len);
			mp_err.backtrace = strndup(str, str_len);
			break;
		case MP_ERROR_DET_CUSTOM_TYPE:
			if (mp_typeof(**data) != MP_STR)
				goto error;
			str = mp_decode_str(data, &str_len);
			mp_err.custom_type = strndup(str, str_len);
			break;
		case MP_ERROR_DET_AD_OBJ_TYPE:
			if (mp_typeof(**data) != MP_STR)
				goto error;
			str = mp_decode_str(data, &str_len);
			mp_err.ad_obj_type = strndup(str, str_len);
			break;
		case MP_ERROR_DET_AD_OBJ_NAME:
			if (mp_typeof(**data) != MP_STR)
				goto error;
			str = mp_decode_str(data, &str_len);
			mp_err.ad_obj_name = strndup(str, str_len);
			break;
		case MP_ERROR_DET_AD_ACCESS_TYPE:
			if (mp_typeof(**data) != MP_STR)
				goto error;
			str = mp_decode_str(data, &str_len);
			mp_err.ad_access_type = strndup(str, str_len);
			break;
		default:
			mp_next(data);
		}
	}

	assert(*data == svp + len);

	err = build_error(&mp_err);
	mp_error_cleanup(&mp_err);
	return err;

error:
	diag_set(ClientError, ER_INVALID_MSGPACK,
		 "Invalid MP_ERROR MsgPack format");
	return NULL;
}
