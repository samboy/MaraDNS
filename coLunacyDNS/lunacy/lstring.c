/*
** $Id: lstring.c,v 2.8.1.1 2007/12/27 13:02:25 roberto Exp $
** String table (keeps all strings handled by Lua)
** See Copyright Notice in lua.h
*/


#include <string.h>

#define lstring_c
#define LUA_CORE

#include "lua.h"

#include "lmem.h"
#include "lobject.h"
#include "lstate.h"
#include "lstring.h"



void luaS_resize (lua_State *L, int newsize) {
  GCObject **newhash;
  stringtable *tb;
  int i;
  if (G(L)->gcstate == GCSsweepstring)
    return;  /* cannot resize during GC traverse */
  newhash = luaM_newvector(L, newsize, GCObject *);
  tb = &G(L)->strt;
  for (i=0; i<newsize; i++) newhash[i] = NULL;
  /* rehash */
  for (i=0; i<tb->size; i++) {
    GCObject *p = tb->hash[i];
    while (p) {  /* for each node in the list */
      GCObject *next = p->gch.next;  /* save next */
      unsigned int h = gco2ts(p)->hash;
      int h1 = lmod(h, newsize);  /* new position */
      lua_assert(cast_int(h%newsize) == lmod(h, newsize));
      p->gch.next = newhash[h1];  /* chain it */
      newhash[h1] = p;
      p = next;
    }
  }
  luaM_freearray(L, tb->hash, tb->size, TString *);
  tb->size = newsize;
  tb->hash = newhash;
}


static TString *newlstr (lua_State *L, const char *str, size_t l,
                                       unsigned int h) {
  TString *ts;
  stringtable *tb;
  if (l+1 > (MAX_SIZET - sizeof(TString))/sizeof(char))
    luaM_toobig(L);
  ts = cast(TString *, luaM_malloc(L, (l+1)*sizeof(char)+sizeof(TString)));
  ts->tsv.len = l;
  ts->tsv.hash = h;
  ts->tsv.marked = luaC_white(G(L));
  ts->tsv.tt = LUA_TSTRING;
  ts->tsv.reserved = 0;
  memcpy(ts+1, str, l*sizeof(char));
  ((char *)(ts+1))[l] = '\0';  /* ending 0 */
  tb = &G(L)->strt;
  h = lmod(h, tb->size);
  ts->tsv.next = tb->hash[h];  /* chain new entry */
  tb->hash[h] = obj2gco(ts);
  tb->nuse++;
  if (tb->nuse > cast(lu_int32, tb->size) && tb->size <= MAX_INT/2)
    luaS_resize(L, tb->size*2);  /* too crowded */
  return ts;
}

// Sip Hash needs well defined 64-bit ints, even on 32-bit systems
#include <stdint.h>
// Sip hash has a 128-bit key which should be fairly random
// This comes from the RadioGatun[32] hash of "https://maradns.samiam.org"
#ifdef FullSipHash
uint64_t sipKey1 = 0xded6cbc72f7eeb4fULL;
uint64_t sipKey2 = 0x81875fe84b1705d7ULL;
#else
uint32_t sipKey1 = 0xded6cbc7;
uint64_t sipKey2 = 0x2f7eeb4f;
#endif

#ifdef FullSipHash
void SipHashSetKey(uint64_t a, uint64_t b) {
#else
void SipHashSetKey(uint32_t a, uint32_t b) {
#endif
  sipKey1 = a;
  sipKey2 = b;
}

#ifndef FullSipHash
// HalfSipHash1-3
uint32_t SipHash(const char *str, size_t l) {
  uint32_t v0, v1, v2, v3, m;
  int shift = 0, round = 0;
  size_t offset = 0;

  // We calculate the hash via SipHash, for security reasons
  v0 = sipKey1;
  v1 = sipKey2;
  v2 = v0 ^ 0x6c796765;
  v3 = v1 ^ 0x74656462;
  m = 0;
  while(offset <= l) {
    if(offset < l) {
      m |= (uint32_t)(str[offset] & 0xff) << shift;  
      shift += 8;
    }
    while(shift >= 32 || offset == l) { // "while" to avoid goto
      if(offset == l && shift != 32) {
        m |= (uint64_t)(l & 0xff) << 24;
        offset++;
      }
      shift = 0;
      v3 ^= m;

      v0 += v1; 
      v1 = (v1 << 5) | (v1 >> 27);
      v1 ^= v0;
      v0 = (v0 << 16) | (v0 >> 16);
      v2 += v3;
      v3 = (v3 << 8) | (v3 >> 24);
      v3 ^= v2; v0 += v3;
      v3 = (v3 << 7) | (v3 >> 25);
      v3 ^= v0; v2 += v1;
      v1 = (v1 << 13) | (v1 >> 19);
      v1 ^= v2;
      v2 = (v2 << 16) | (v2 >> 16);

      v0 ^= m;
      shift = 0;
      m = 0;
    }
    offset++;
  }   
  v2 ^= 255;
  for(round = 0; round < 3; round++) {
    v0 += v1; 
    v1 = (v1 << 5) | (v1 >> 27);
    v1 ^= v0;
    v0 = (v0 << 16) | (v0 >> 16);
    v2 += v3;
    v3 = (v3 << 8) | (v3 >> 24);
    v3 ^= v2; v0 += v3;
    v3 = (v3 << 7) | (v3 >> 25);
    v3 ^= v0; v2 += v1;
    v1 = (v1 << 13) | (v1 >> 19);
    v1 ^= v2;
    v2 = (v2 << 16) | (v2 >> 16);
  }
  return v1 ^ v3;
} 
#else // FullSipHash
uint64_t SipHash(const char *str, size_t l) {
  uint64_t v0, v1, v2, v3, m;
  int shift = 0, round = 0;
  size_t offset = 0;

  // We calculate the hash via SipHash, for security reasons
  v0 = sipKey1 ^ 0x736f6d6570736575ULL;
  v1 = sipKey2 ^ 0x646f72616e646f6dULL;
  v2 = sipKey1 ^ 0x6c7967656e657261ULL;
  v3 = sipKey2 ^ 0x7465646279746573ULL;
  m = 0;
  while(offset <= l) {
    if(offset < l) {
      m |= (uint64_t)(str[offset] & 0xff) << shift;  
      shift += 8;
    }
    while(shift >= 64 || offset == l) { // "while" to avoid goto
      if(offset == l && shift != 64) {
        m |= (uint64_t)(l & 0xff) << 56;
        offset++;
      }
      shift = 0;
      v3 ^= m;
#ifdef SIP24
      for(round = 0; round < 2; round++) {
#endif // SIP24
        v0 += v1; v2 += v3;
        v1 = (v1 << 13) | (v1 >> 51);
        v3 = (v3 << 16) | (v3 >> 48);
        v1 ^= v0; v3 ^= v2;
        v0 = (v0 << 32) | (v0 >> 32);
        v2 += v1; v0 += v3;
        v1 = (v1 << 17) | (v1 >> 47);
        v3 = (v3 << 21) | (v3 >> 43);
        v1 ^= v2; v3 ^= v0;
        v2 = (v2 << 32) | (v2 >> 32);
#ifdef SIP24
      }
#endif // SIP24
      v0 ^= m;
      shift = 0;
      m = 0;
    }
    offset++;
  }   
  v2 ^= 255;
#ifdef SIP24
  for(round = 0; round < 4; round++) {
#else // SIP24
  for(round = 0; round < 3; round++) {
#endif // SIP24
    v0 += v1; v2 += v3;
    v1 = (v1 << 13) | (v1 >> 51);
    v3 = (v3 << 16) | (v3 >> 48);
    v1 ^= v0; v3 ^= v2;
    v0 = (v0 << 32) | (v0 >> 32);
    v2 += v1; v0 += v3;
    v1 = (v1 << 17) | (v1 >> 47);
    v3 = (v3 << 21) | (v3 >> 43);
    v1 ^= v2; v3 ^= v0;
    v2 = (v2 << 32) | (v2 >> 32);
  }
  return v0 ^ v1 ^ v2 ^ v3;
} 
#endif // FullSipHash

TString *luaS_newlstr (lua_State *L, const char *str, size_t l) {
  GCObject *o;
  unsigned int h = cast(unsigned int, l);  /* seed */
  h = (unsigned int)SipHash(str,l); 
  for (o = G(L)->strt.hash[lmod(h, G(L)->strt.size)];
       o != NULL;
       o = o->gch.next) {
    TString *ts = rawgco2ts(o);
    if (ts->tsv.len == l && (memcmp(str, getstr(ts), l) == 0)) {
      /* string may be dead */
      if (isdead(G(L), o)) changewhite(o);
      return ts;
    }
  }
  return newlstr(L, str, l, h);  /* not found */
}


Udata *luaS_newudata (lua_State *L, size_t s, Table *e) {
  Udata *u;
  if (s > MAX_SIZET - sizeof(Udata))
    luaM_toobig(L);
  u = cast(Udata *, luaM_malloc(L, s + sizeof(Udata)));
  u->uv.marked = luaC_white(G(L));  /* is not finalized */
  u->uv.tt = LUA_TUSERDATA;
  u->uv.len = s;
  u->uv.metatable = NULL;
  u->uv.env = e;
  /* chain it on udata list (after main thread) */
  u->uv.next = G(L)->mainthread->next;
  G(L)->mainthread->next = obj2gco(u);
  return u;
}

