
#ifndef LUAU_API_H
#define LUAU_API_H

#include <stddef.h>
#include <stdint.h>

typedef struct lua_State lua_State;

#define LUA_OK 0
#define LUA_ERRRUN 2
#define LUA_ERRSYNTAX 3
#define LUA_ERRMEM 4
#define LUA_ERRERR 5

#define LUA_REGISTRYINDEX (-10000)
#define LUA_ENVIRONINDEX (-10001)
#define LUA_GLOBALSINDEX (-10002)

#ifndef RTLD_NOW
#define RTLD_NOW 0x00002
#endif
#ifndef RTLD_GLOBAL
#define RTLD_GLOBAL 0x00100
#endif

typedef int (*lua_gettop_t)(lua_State *L);
typedef void (*lua_settop_t)(lua_State *L, int idx);
typedef void (*lua_pushvalue_t)(lua_State *L, int idx);
typedef void (*lua_remove_t)(lua_State *L, int idx);
typedef void (*lua_insert_t)(lua_State *L, int idx);
typedef void (*lua_replace_t)(lua_State *L, int idx);
typedef int (*lua_checkstack_t)(lua_State *L, int sz);

typedef void (*lua_pushnil_t)(lua_State *L);
typedef void (*lua_pushnumber_t)(lua_State *L, double n);
typedef void (*lua_pushinteger_t)(lua_State *L, int n);
typedef const char *(*lua_pushlstring_t)(lua_State *L, const char *s,
                                         size_t len);
typedef const char *(*lua_pushstring_t)(lua_State *L, const char *s);
typedef void (*lua_pushboolean_t)(lua_State *L, int b);
typedef void (*lua_pushcclosure_t)(lua_State *L, void *fn, int n);
typedef void (*lua_pushlightuserdata_t)(lua_State *L, void *p);

typedef double (*lua_tonumber_t)(lua_State *L, int idx);
typedef int (*lua_tointeger_t)(lua_State *L, int idx);
typedef int (*lua_toboolean_t)(lua_State *L, int idx);
typedef const char *(*lua_tolstring_t)(lua_State *L, int idx, size_t *len);
typedef size_t (*lua_objlen_t)(lua_State *L, int idx);
typedef void *(*lua_touserdata_t)(lua_State *L, int idx);
typedef lua_State *(*lua_tothread_t)(lua_State *L, int idx);
typedef const void *(*lua_topointer_t)(lua_State *L, int idx);

typedef int (*lua_type_t)(lua_State *L, int idx);
typedef const char *(*lua_typename_t)(lua_State *L, int tp);
typedef int (*lua_isnumber_t)(lua_State *L, int idx);
typedef int (*lua_isstring_t)(lua_State *L, int idx);
typedef int (*lua_iscfunction_t)(lua_State *L, int idx);
typedef int (*lua_isuserdata_t)(lua_State *L, int idx);

typedef void (*lua_gettable_t)(lua_State *L, int idx);
typedef void (*lua_getfield_t)(lua_State *L, int idx, const char *k);
typedef void (*lua_rawget_t)(lua_State *L, int idx);
typedef void (*lua_rawgeti_t)(lua_State *L, int idx, int n);
typedef void (*lua_createtable_t)(lua_State *L, int narr, int nrec);
typedef void *(*lua_newuserdata_t)(lua_State *L, size_t sz);
typedef int (*lua_getmetatable_t)(lua_State *L, int objindex);

typedef void (*lua_settable_t)(lua_State *L, int idx);
typedef void (*lua_setfield_t)(lua_State *L, int idx, const char *k);
typedef void (*lua_rawset_t)(lua_State *L, int idx);
typedef void (*lua_rawseti_t)(lua_State *L, int idx, int n);
typedef int (*lua_setmetatable_t)(lua_State *L, int objindex);

typedef void (*lua_getglobal_t)(lua_State *L, const char *name);
typedef void (*lua_setglobal_t)(lua_State *L, const char *name);

typedef void (*lua_call_t)(lua_State *L, int nargs, int nresults);
typedef int (*lua_pcall_t)(lua_State *L, int nargs, int nresults, int errfunc);

typedef int (*luaL_loadbuffer_t)(lua_State *L, const char *buff, size_t sz,
                                 const char *name);
typedef int (*luaL_loadstring_t)(lua_State *L, const char *s);

typedef int (*luaL_ref_t)(lua_State *L, int t);
typedef void (*luaL_unref_t)(lua_State *L, int t, int ref);

typedef struct luau_api {
  
  uintptr_t sober_base;
  lua_State *L;

  
  int initialized;
  int functions_resolved;

  
  lua_gettop_t gettop;
  lua_settop_t settop;
  lua_pushvalue_t pushvalue;
  lua_remove_t remove;
  lua_insert_t insert;
  lua_replace_t replace;
  lua_checkstack_t checkstack;

  
  lua_pushnil_t pushnil;
  lua_pushnumber_t pushnumber;
  lua_pushinteger_t pushinteger;
  lua_pushlstring_t pushlstring;
  lua_pushstring_t pushstring;
  lua_pushboolean_t pushboolean;
  lua_pushcclosure_t pushcclosure;
  lua_pushlightuserdata_t pushlightuserdata;

  
  lua_tonumber_t tonumber;
  lua_tointeger_t tointeger;
  lua_toboolean_t toboolean;
  lua_tolstring_t tolstring;
  lua_objlen_t objlen;
  lua_touserdata_t touserdata;
  lua_tothread_t tothread;
  lua_topointer_t topointer;

  
  lua_type_t type;
  lua_typename_t lua_typename;
  lua_isnumber_t isnumber;
  lua_isstring_t isstring;
  lua_iscfunction_t iscfunction;
  lua_isuserdata_t isuserdata;

  
  lua_gettable_t gettable;
  lua_getfield_t getfield;
  lua_rawget_t rawget;
  lua_rawgeti_t rawgeti;
  lua_createtable_t createtable;
  lua_newuserdata_t newuserdata;
  lua_getmetatable_t getmetatable;

  lua_settable_t settable;
  lua_setfield_t setfield;
  lua_rawset_t rawset;
  lua_rawseti_t rawseti;
  lua_setmetatable_t setmetatable;

  
  lua_getglobal_t getglobal;
  lua_setglobal_t setglobal;

  
  lua_call_t call;
  lua_pcall_t pcall;

  
  luaL_loadbuffer_t loadbuffer;
  luaL_loadstring_t loadstring;

  
  luaL_ref_t ref;
  luaL_unref_t unref;

} luau_api_t;

typedef struct {
  const char *name;
  const uint8_t *pattern;
  const char *mask;
  size_t length;
  int offset_from_match; 
} func_pattern_t;

typedef struct {
  const char *name;
  uintptr_t address;
  int confidence; 
} scan_result_t;

int luau_api_init(luau_api_t *api);

uintptr_t find_sober_base(void);

lua_State *find_lua_state(uintptr_t sober_base);

int validate_lua_state(lua_State *L, uintptr_t sober_base);

uintptr_t scan_for_function(uintptr_t base, size_t size,
                            const func_pattern_t *pattern);

int resolve_functions(luau_api_t *api);

int execute_script(luau_api_t *api, const char *script, char *output,
                   size_t output_size);

int safe_call(void *func, lua_State *L, const char *arg);

#endif
