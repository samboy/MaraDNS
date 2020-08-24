/*
** $Id: loslib.c,v 1.19.1.3 2008/01/18 16:38:18 roberto Exp $
** Standard Operating System library
** See Copyright Notice in lua.h
*/


#include <errno.h>
#include <locale.h>
#include <stdlib.h>
#include <string.h>

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
  {NULL, NULL}
};

/* }====================================================== */



LUALIB_API int luaopen_os (lua_State *L) {
  luaL_register(L, LUA_OSLIBNAME, syslib);
  return 1;
}

