/*
** $Id: loslib.c,v 1.19.1.3 2008/01/18 16:38:18 roberto Exp $
** Standard Operating System library
** See Copyright Notice in lua.h
*/


#include <errno.h>
#include <locale.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#ifdef MINGW
#include <wininet.h>
#else
#include <time.h>
#endif // MINGW

#define loslib_c
#define LUA_LIB

#include "lua.h"

#include "lauxlib.h"
#include "lualib.h"


static int os_pushresult (lua_State *L, int i, const char *filename) {
  int en = errno;  /* calls to Lua API may change this value */
  if (i) {
    lua_pushboolean(L, 1);
    return 1;
  }
  else {
    lua_pushnil(L);
    lua_pushfstring(L, "%s: %s", filename, strerror(en));
    lua_pushinteger(L, en);
    return 3;
  }
}


static int os_execute (lua_State *L) {
  lua_pushinteger(L, system(luaL_optstring(L, 1, NULL)));
  return 1;
}


static int os_remove (lua_State *L) {
  const char *filename = luaL_checkstring(L, 1);
  return os_pushresult(L, remove(filename) == 0, filename);
}


static int os_rename (lua_State *L) {
  const char *fromname = luaL_checkstring(L, 1);
  const char *toname = luaL_checkstring(L, 2);
  return os_pushresult(L, rename(fromname, toname) == 0, fromname);
}


static int os_tmpname (lua_State *L) {
  char buff[LUA_TMPNAMBUFSIZE];
  int err;
  lua_tmpnam(buff, err);
  if (err)
    return luaL_error(L, "unable to generate a unique filename");
  lua_pushstring(L, buff);
  return 1;
}


static int os_getenv (lua_State *L) {
  lua_pushstring(L, getenv(luaL_checkstring(L, 1)));  /* if NULL push nil */
  return 1;
}


/*
** {======================================================
** Time/Date operations
** { year=%Y, month=%m, day=%d, hour=%H, min=%M, sec=%S,
**   wday=%w+1, yday=%j, isdst=? }
** =======================================================
*/

/* (Disabled to remove C compile warning)
static void setfield (lua_State *L, const char *key, int value) {
  lua_pushinteger(L, value);
  lua_setfield(L, -2, key);
}
*/

/* (Disabled to remove C compile warning; / made - to remove another warning)
static void setboolfield (lua_State *L, const char *key, int value) {
  if (value < 0)  -* undefined? *-
    return;  -* does not set field *-
  lua_pushboolean(L, value);
  lua_setfield(L, -2, key);
}
*/

/* (Disabled to remove C compile warning)
static int getboolfield (lua_State *L, const char *key) {
  int res;
  lua_getfield(L, -1, key);
  res = lua_isnil(L, -1) ? -1 : lua_toboolean(L, -1);
  lua_pop(L, 1);
  return res;
}
*/


/* (Disabled to remove C compile warning)
static int getfield (lua_State *L, const char *key, int d) {
  int res;
  lua_getfield(L, -1, key);
  if (lua_isnumber(L, -1))
    res = (int)lua_tointeger(L, -1);
  else {
    if (d < 0)
      return luaL_error(L, "field " LUA_QS " missing in date table", key);
    res = d;
  }
  lua_pop(L, 1);
  return res;
} 
*/

/* }====================================================== */


static int os_setlocale (lua_State *L) {
  static const int cat[] = {LC_ALL, LC_COLLATE, LC_CTYPE, LC_MONETARY,
                      LC_NUMERIC, LC_TIME};
  static const char *const catnames[] = {"all", "collate", "ctype", "monetary",
     "numeric", "time", NULL};
  const char *l = luaL_optstring(L, 1, NULL);
  int op = luaL_checkoption(L, 2, "all", catnames);
  lua_pushstring(L, setlocale(cat[op], l));
  return 1;
}

/* Note that this code is Y2038 compliant, even with a 32-bit time_t.  
 *
 * On 32-bit time_t UNIX compatible systems, things will run OK until 2106.
 * As I type this, only legacy UNIX-like systems still have a 32-bit time_t
 * (Notably, Linux distros using older kernels such as CentOS and FreeBSD
 *  on i386 chips, but even here FreeBSD uses a 32-bit unsigned time_t.
 *  Note that CentOS only has a 32-bit time_t when one goes out of their way
 *  to compile a program as 32-bit; the default 64-bit environment has a
 *  64-bit time_t)
 *
 * On 32-bit Windows systems, which use a 64-bit “FileTime” time stamp, 
 * things will run OK until 30,827 or 30,828.  
 *
 * This code has been tested in Windows XP (32-bit binary, using FileTime) 
 * and CentOS 8 (32-bit binary with 32-bit time_t); in both cases, 
 * os.time() returns a correct timestamp when we move the clock forward 
 * to 2040.
 */
static int os_time (lua_State *L) {
#ifndef MINGW
  time_t t;
  int64_t tt;
  if (lua_isnoneornil(L, 1))  /* called without args? */
    t = time(NULL);  /* get current time */
  else {
    // Lunacy only supports getting the current time
    lua_pushnil(L);
    return 1;
  }
  if(t < -1) {
    tt = (int64_t)t + 4294967296ULL;
  } else {
    tt = (int64_t)t;
  }
  if (t == (time_t)(-1))
    lua_pushnil(L);
  else
    lua_pushnumber(L, (lua_Number)tt);
  return 1;
#else
  /* Convert Windows "filetime" in to Lua number */
  uint64_t t;
  FILETIME win_time = { 0, 0 };
  GetSystemTimeAsFileTime(&win_time);
  t = win_time.dwHighDateTime & 0xffffffff;
  t <<= 32;
  t |= (win_time.dwLowDateTime & 0xffffffff);
  t /= 10000000;
  t -= 11644473600LL;
  lua_pushnumber(L, (lua_Number)t); 
  return 1;
#endif // MINGW
}

static int os_exit (lua_State *L) {
  exit(luaL_optint(L, 1, EXIT_SUCCESS));
}

static const luaL_Reg syslib[] = {
  {"execute",   os_execute},
  {"exit",      os_exit},
  {"getenv",    os_getenv},
  {"remove",    os_remove},
  {"rename",    os_rename},
  {"setlocale", os_setlocale},
  {"tmpname",   os_tmpname},
  {"time",      os_time},
  {NULL, NULL}
};

/* }====================================================== */



LUALIB_API int luaopen_os (lua_State *L) {
  luaL_register(L, LUA_OSLIBNAME, syslib);
  return 1;
}

