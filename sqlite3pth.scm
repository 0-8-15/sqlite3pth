;; (C) 2008, 2010, 2015 Jörg F. Wittenberger -*-Scheme-*-

;; TODO: integrate with http://www.chust.org/fossils/dbi/index

(declare
 (fixnum)
 (usual-integrations)
 (disable-interrupts)

; (no-procedure-checks-for-usual-bindings)
 #;(bound-to-procedure
  mutex-lock! mutex-unlock!)
 (foreign-declare #<<EOF

#include <pthread.h>

//#define TRACE 1

#define CHECK_PROTOCOL 1

#if 1

#define L_malloc(x) malloc(x)
#define L_free(x) free(x)

#else

int n_malloc = 0;

static void * L_malloc(size_t n)
{
 n_malloc++;
 fprintf(stderr, "malloced %d\n", n_malloc);
 return malloc(n);
}

static void L_free(void *x)
{
 n_malloc--;
 free(x);
}

#endif

typedef C_word obj;
#define FALSE_OBJ C_SCHEME_FALSE

#include "sqlite/sqlite3.h"
#include <assert.h>

static int rs_sqlite3_auth_unrestricted(void* userdata, int opcode,
				 const char* arg1, const char* arg2,
				 const char* dbname, const char* trigger)
{
  return SQLITE_OK;
}

static void sqlite3_set_authorizer_unrestricted(sqlite3 *cnx)
{
 sqlite3_set_authorizer(cnx, rs_sqlite3_auth_unrestricted, NULL);
}

/* ** AUTHORIZATION HANDLING ** */

static int rs_sqlite3_auth_restricted(void* userdata, int opcode,
			       const char* arg1, const char* arg2,
			       const char* dbname, const char* trigger)
{
  switch(opcode) {
  case SQLITE_CREATE_INDEX:	/* Index Name      Table Name      */
  case SQLITE_REINDEX:
  case SQLITE_CREATE_TABLE:	/* Table Name      NULL            */
  case SQLITE_CREATE_VTABLE:    /* Table Name      Module Name     */
  case SQLITE_ALTER_TABLE:      /* Database Name   Table Name      */
  case SQLITE_CREATE_TEMP_INDEX: /* Index Name      Table Name     */
  case SQLITE_CREATE_TEMP_TABLE: /* Table Name      NULL           */
  case SQLITE_CREATE_TEMP_TRIGGER: /* Trigger Name    Table Name   */
  case SQLITE_CREATE_TEMP_VIEW:	/* View Name       NULL            */
  case SQLITE_CREATE_TRIGGER:	/* Trigger Name    Table Name      */
  case SQLITE_CREATE_VIEW:	/* View Name       NULL            */
  case SQLITE_DELETE:		/* Table Name      NULL            */
  case SQLITE_DROP_INDEX:	/* Index Name      Table Name      */
  case SQLITE_DROP_TABLE:	/* Table Name      NULL            */
  case SQLITE_DROP_VTABLE:      /* Table Name      Module Name     */
  case SQLITE_DROP_TEMP_INDEX:	/* Index Name      Table Name      */
  case SQLITE_DROP_TEMP_TABLE:	/* Table Name      NULL            */
  case SQLITE_DROP_TEMP_TRIGGER: /* Trigger Name    Table Name     */
  case SQLITE_DROP_TEMP_VIEW:   /* View Name       NULL            */
  case SQLITE_DROP_TRIGGER:	/* Trigger Name    Table Name      */
  case SQLITE_DROP_VIEW:	/* View Name       NULL            */
  case SQLITE_INSERT:		/* Table Name      NULL            */
  case SQLITE_PRAGMA:		/* Pragma Name     1st arg or NULL */
  case SQLITE_READ:		/* Table Name      Column Name     */
  case SQLITE_SELECT:		/* NULL            NULL            */
#if SQLITE_VERSION_NUMBER > 3003007
  case SQLITE_FUNCTION:		/* Function Name   NULL            */
#endif
  case SQLITE_TRANSACTION:	/* NULL            NULL            */
  case SQLITE_UPDATE:		/* Table Name      Column Name     */
  case SQLITE_ANALYZE:          /* Table Name      NULL            */
  case SQLITE_RECURSIVE:        /* NULL      NULL                  */
    return SQLITE_OK;
  case SQLITE_ATTACH:		/* Filename        NULL            */
  case SQLITE_DETACH:		/* Database Name   NULL            */
  default:
fprintf(stderr, "auth_restricted deny %d\n", opcode);
    return SQLITE_DENY;
  }
}

/* KLUDGE: FIXME: we need to know what temp tables are, not code them hard */

static int is_temporary_table(void *userdata, const char *table)
{
 if (strcmp(table, "sqlite_temp_master") == 0) return 1;
 if (strcmp(table, "current_message") == 0) return 1;
 return 0;
}

static int rs_sqlite3_auth_restricted_ro(void* userdata, int opcode,
			          const char* arg1, const char* arg2,
				  const char* dbname, const char* trigger)
{
  switch(opcode) {
  case SQLITE_CREATE_INDEX:	/* Index Name      Table Name      */
  case SQLITE_CREATE_TABLE:	/* Table Name      NULL            */
  case SQLITE_ALTER_TABLE:      /* Database Name   Table Name      */
    return SQLITE_DENY;
  case SQLITE_CREATE_TEMP_INDEX: /* Index Name      Table Name     */
  case SQLITE_CREATE_TEMP_TABLE: /* Table Name      NULL           */
  case SQLITE_CREATE_TEMP_TRIGGER: /* Trigger Name    Table Name   */
  case SQLITE_CREATE_TEMP_VIEW:	/* View Name       NULL            */
    return SQLITE_OK;
  case SQLITE_CREATE_TRIGGER:	/* Trigger Name    Table Name      */
  case SQLITE_CREATE_VIEW:	/* View Name       NULL            */
  case SQLITE_DELETE:		/* Table Name      NULL            */
  case SQLITE_DROP_INDEX:	/* Index Name      Table Name      */
  case SQLITE_DROP_TABLE:	/* Table Name      NULL            */
    return SQLITE_DENY;
  case SQLITE_DROP_TEMP_INDEX:	/* Index Name      Table Name      */
  case SQLITE_DROP_TEMP_TABLE:	/* Table Name      NULL            */
  case SQLITE_DROP_TEMP_TRIGGER: /* Trigger Name    Table Name     */
  case SQLITE_DROP_TEMP_VIEW:   /* View Name       NULL            */
    return SQLITE_OK;
  case SQLITE_DROP_TRIGGER:	/* Trigger Name    Table Name      */
  case SQLITE_DROP_VIEW:	/* View Name       NULL            */
    return SQLITE_DENY;
  case SQLITE_INSERT:		/* Table Name      NULL            */
    if (is_temporary_table(userdata,arg1))
    return SQLITE_OK;
    return SQLITE_DENY;
  case SQLITE_PRAGMA:		/* Pragma Name     1st arg or NULL */
    return SQLITE_DENY;
  case SQLITE_READ:		/* Table Name      Column Name     */
  case SQLITE_SELECT:		/* NULL            NULL            */
#if SQLITE_VERSION_NUMBER > 3003007
  case SQLITE_FUNCTION:		/* Function Name   NULL            */
#endif
  case SQLITE_RECURSIVE:        /* NULL      NULL                  */
    return SQLITE_OK;
  case SQLITE_TRANSACTION:	/* NULL            NULL            */
    return SQLITE_DENY;
  case SQLITE_UPDATE:		/* Table Name      Column Name     */

  /* FIXME: this is somehow needed to select from fts tables. */
#if 0
    if (is_temporary_table(userdata,arg1))
    return SQLITE_OK;
    return SQLITE_DENY;
#else
    return SQLITE_OK;
#endif

  case SQLITE_ATTACH:		/* Filename        NULL            */
  case SQLITE_DETACH:		/* Database Name   NULL            */
  default:
    return SQLITE_DENY;
  }
}

/*  ** misc functions ** */

static void sqlite3_concat(sqlite3_context* ctx, int argc, sqlite3_value** argv)
{
  int len=0, i=0, j=0;
  char *r = NULL;
  for(;i<argc; ++i) len+=sqlite3_value_bytes(argv[i]);
  r = malloc(len+1);
  for(i=0, j=0; i<argc; ++i) {
    int s = sqlite3_value_bytes(argv[i]);
    strncpy(r+j, (const char*)sqlite3_value_text(argv[i]), s);
    j += s;
  }
  r[j]='\0';
  sqlite3_result_text(ctx, r, len, free);
}

static int sq_sqlite3_create_functions(sqlite3 *conn)
{
  return sqlite3_create_function(conn, "concat", -1, SQLITE_UTF8 | SQLITE_DETERMINISTIC,
				 NULL, sqlite3_concat, NULL, NULL);
}

static void sqlite3_set_authorizer_restricted_ro(sqlite3 *cnx)
{
 sqlite3_set_authorizer(cnx, rs_sqlite3_auth_restricted_ro, NULL);
}

static void sqlite3_set_authorizer_restricted(sqlite3 *cnx)
{
 sqlite3_set_authorizer(cnx, rs_sqlite3_auth_restricted, NULL);
}

/* setup function table */

static void sqlite3_setup_full(sqlite3 *cnx)
{
  sq_sqlite3_create_functions(cnx);
}

static void sqlite3_setup_restricted(sqlite3 *cnx)
{
  sqlite3_set_authorizer(cnx, rs_sqlite3_auth_restricted, NULL);
  sq_sqlite3_create_functions(cnx);
}

static void sqlite3_setup_restricted_ro(sqlite3 *cnx)
{
  sqlite3_set_authorizer(cnx, rs_sqlite3_auth_restricted_ro, NULL);
  sq_sqlite3_create_functions(cnx);
}

static void (*setup_table[4])(sqlite3 *) = {
  NULL,
  sqlite3_setup_full,
  sqlite3_setup_restricted,
  sqlite3_setup_restricted_ro
};

static void sqlite3_setup(sqlite3 *cnx, int i)
{
  void (*f)(sqlite3 *);
  assert(i<4);
  f=setup_table[i];
  if(f) (*f)(cnx);
}

static pthread_mutex_t the_shared_memory_mux;
static pthread_cond_t the_shared_memory_cond;
static struct callback_args *the_shared_memory_for_open = NULL;

void lock_callback_open_parameters(struct callback_args * x)
{
  pthread_mutex_lock(&the_shared_memory_mux);
  while( the_shared_memory_for_open != NULL )
    pthread_cond_wait(&the_shared_memory_cond, &the_shared_memory_mux);
  the_shared_memory_for_open = x;
  pthread_mutex_unlock(&the_shared_memory_mux);
}

void unlock_callback_open_parameters()
{
  the_shared_memory_for_open = NULL;
  pthread_cond_signal(&the_shared_memory_cond);
}

typedef int (*C_pthread_request_function_t)(void *);
extern int
start_asynchronous_request(C_pthread_request_function_t function,
		             void *data, void *callback);

extern void
C_interrupt_call(void *callback, void *converter, void *result);

struct callback_args {
  pthread_mutex_t mux;
  pthread_cond_t cond;
  C_GC_ROOT *ref;
  unsigned int op;
  size_t size;
  int amount;
  sqlite_int64 offset;
  void *buf;
  /* char buf[1]; */
};

struct open_args {
  sqlite3 *cnx;
  int setup;
  struct callback_args *sm;
  char *vfs;
  char dbn[2];
};

static int
pthread_sqlite3_open(void *data)
{
  struct open_args *a = data;
  int rc;

#ifdef TRACE
fprintf(stderr, "DB %s vfs %s SM %p\n", a->dbn, a->vfs, a->sm);
#endif

  if(a->sm != NULL) {
    lock_callback_open_parameters(a->sm);
  }

  rc = sqlite3_open_v2( a->dbn,
			&a->cnx,
			( a->setup == 3 ? SQLITE_OPEN_READONLY :
			  ( SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE ) )
                        | SQLITE_OPEN_NOMUTEX,
			a->vfs);
  /* unlock_callback_open_parameters(); done within open ASAP */
  sqlite3_setup(a->cnx, a->setup);

  return SQLITE_OK;
}

struct sqlite3_db {
  sqlite3 *cnx;
  size_t bufsize;
  void *buf;
};

static int pthread_sqlite3_close(void *data)
{
  struct sqlite3_db *a = data;
  int rc = (/*sqlite3MemdebugDump("/tmp/sqlite"),*/ sqlite3_close(a->cnx));
  L_free(a->buf);
  L_free(a);
  return rc;
}

struct prepare_args {
  sqlite3_stmt *stmt;
  int tail;
  sqlite3 *db;
  int sql_len;
  int offset;
  char sql[1];
};

static int pthread_sqlite3_prepare(void *data)
{
  struct prepare_args *a = data;
  int rc;
  const char *tail;

#ifdef TRACE
  fprintf(stderr, "prepar %p >>%s<< %d %d\n", a->db, a->sql, a->offset, a->sql_len);
#endif

  rc = sqlite3_prepare_v2( a->db,
			   a->sql + a->offset,
			   a->sql_len - a->offset,
			   &a->stmt,
			   &tail );
  if (a->stmt != NULL) {
    a->tail = tail - a->sql;
  }
  return rc;
}

/*
** 2009 Juli 24
**
** This file contains OS interface code that is used with Askemos(R).
**/

/*
** standard include files.
*/
#include <string.h>
#include <pthread.h>

/*
** Maximum pathname length supported by the callback backend.
*/
#define CALLBACK_MAX_PATHNAME 512
#define CB_IO_TYPE_BLKSZ  1
#define CB_IO_TYPE_FSIZE  2
#define CB_IO_TYPE_READ   3
#define CB_IO_TYPE_WRITE  4
#define CB_IO_TYPE_TRUNC  5
#define CB_IO_TYPE_CLOSE  6

#define CB_OP_CALL 2
#define CB_OP_RETURN 1
#define CB_OP_BUSY 3
#define CB_OP_SHIFT 2

/*
** Pointer-Makros
*/
/* pointer to the parent sqlite3_vfs structure (e.g. unix) */
sqlite3_vfs *pVfs = NULL; 

// "host" callback
static void *the_callback_callback = NULL;
static void *the_callback_arg_converter = NULL;

typedef struct callback_file callback_file;
struct callback_file {
  sqlite3_io_methods *ioMethods;
  const char* zName;

  /* shared memory
   *
   * form: #((int opcode) (string buf) (int amount) (int offset) (pointer (condition done))
   */
  struct callback_args *sm;
  
  // pointer to the sqlite3_file structure of the parent vfs (e.g. unix vfs)
  sqlite3_file pReal[1];
};

/*
** Method declarations for callback_file.
*/
static int callbackClose(sqlite3_file*);
static int callbackRead(sqlite3_file*, void*, int iAmt, sqlite3_int64 iOfst);
static int callbackWrite(sqlite3_file*,const void*,int iAmt, sqlite3_int64 iOfst);
static int callbackTruncate(sqlite3_file*, sqlite3_int64 size);
static int callbackFileSize(sqlite3_file*, sqlite3_int64 *pSize);
static int callbackFileControl(sqlite3_file*, int op, void *pArg);
static int callbackSectorSize(sqlite3_file*);
static int callbackDeviceCharacteristics(sqlite3_file*);

static int callbackCloseNot(sqlite3_file*);
static int callbackReadNot(sqlite3_file*, void*, int iAmt, sqlite3_int64 iOfst);
static int callbackWriteNot(sqlite3_file*,const void*,int iAmt, sqlite3_int64 iOfst);
static int callbackTruncateNot(sqlite3_file*, sqlite3_int64 size);
static int callbackSyncNot(sqlite3_file*, int flags);
static int callbackFileSizeNot(sqlite3_file*, sqlite3_int64 *pSize);
static int callbackSyncNot(sqlite3_file*, int flags);
static int callbackLockNot(sqlite3_file*, int);
static int callbackUnlockNot(sqlite3_file*, int);
static int callbackCheckReservedLockNot(sqlite3_file*, int *pResOut);
static int callbackSectorSizeNot(sqlite3_file*);

/*
** Method declarations for callback_vfs.
*/
static int callbackOpen(sqlite3_vfs*, const char *, sqlite3_file*, int , int *);
static int callbackDelete(sqlite3_vfs*, const char *zName, int syncDir);
static int callbackAccess(sqlite3_vfs*, const char *zName, int flags, int *);
static int callbackFullPathname(sqlite3_vfs*, const char *zName, int, char *zOut);
static void *callbackDlOpen(sqlite3_vfs*, const char *zFilename);
static void callbackDlError(sqlite3_vfs*, int nByte, char *zErrMsg);
static void (*callbackDlSym(sqlite3_vfs *pVfs, void *p, const char*zSym))(void);
static void callbackDlClose(sqlite3_vfs*, void*);
static int callbackRandomness(sqlite3_vfs*, int nByte, char *zOut);
static int callbackSleep(sqlite3_vfs*, int microseconds);
static int callbackCurrentTime(sqlite3_vfs*, double*);

static sqlite3_vfs callback_vfs = {
  3,                      /* iVersion */
  sizeof(callback_file),   /* szOsFile */
  CALLBACK_MAX_PATHNAME,   /* mxPathname */
  0,                      /* pNext */
  "askemos",              /* zName */
  0,                      /* pAppData */
  callbackOpen,            /* xOpen */
  callbackDelete,          /* xDelete */
  callbackAccess,          /* xAccess */
  callbackFullPathname,    /* xFullPathname */
  callbackDlOpen,          /* xDlOpen */
  callbackDlError,         /* xDlError */
  callbackDlSym,           /* xDlSym */
  callbackDlClose,         /* xDlClose */
  callbackRandomness,      /* xRandomness */
  callbackSleep,           /* xSleep */
  callbackCurrentTime,      /* xCurrentTime */
  0,                            /* xGetLastError */
  0,                            /* xCurrentTimeInt64 */
  0,                            /* xSetSystemCall */
  0,                            /* xGetSystemCall */
  0,                            /* xNextSystemCall */
};

static sqlite3_io_methods callback_io_methods = {
  1,                                 /* iVersion */
  callbackClose,                      /* xClose */
  callbackRead,                       /* xRead */
  callbackWrite,                      /* xWrite */
  callbackTruncate,                   /* xTruncate */
  callbackSyncNot,                    /* xSync */
  callbackFileSize,                   /* xFileSize */
  callbackLockNot,                    /* xLock */
  callbackUnlockNot,                  /* xUnlock */
  callbackCheckReservedLockNot,       /* xCheckReservedLock */
  callbackFileControl,                /* xFileControl */
  callbackSectorSize,                 /* xSectorSize */
  callbackDeviceCharacteristics       /* xDeviceCharacteristics */
};

static sqlite3_io_methods callback_io_noop_methods = {
  1,                                  /* iVersion */
  callbackCloseNot,                   /* xClose */
  callbackReadNot,                    /* xRead */
  callbackWriteNot,                   /* xWrite */
  callbackTruncateNot,                /* xTruncate */
  callbackSyncNot,                    /* xSync */
  callbackFileSizeNot,                /* xFileSize */
  callbackLockNot,                    /* xLock */
  callbackUnlockNot,                  /* xUnlock */
  callbackCheckReservedLockNot,       /* xCheckReservedLock */
  callbackFileControl,                /* xFileControl */
  callbackSectorSizeNot,                 /* xSectorSize */
  callbackDeviceCharacteristics       /* xDeviceCharacteristics */
};

/*
** Open an callback file handle.
*/

static int callbackOpen(
  sqlite3_vfs *pCallbackVfs,
  const char *zName,
  sqlite3_file *pFile,
  int flags,
  int *pOutFlags
){
  callback_file *p = (callback_file *) pFile;
  /* Only for main db, to save energy. */
  if(flags & SQLITE_OPEN_MAIN_DB) {
#ifdef TRACE
    fprintf(stderr, "A open Main %s\n", zName);
#endif
    p->ioMethods = &callback_io_methods;
    p->zName = zName;
    p->sm = the_shared_memory_for_open;
    unlock_callback_open_parameters();
    return SQLITE_OK;
  } else if (flags & SQLITE_OPEN_MAIN_JOURNAL) {
    p->ioMethods = &callback_io_noop_methods;
    return SQLITE_OK;
  } else if (flags & SQLITE_OPEN_WAL) {
    p->ioMethods = &callback_io_noop_methods;
    return SQLITE_OK;
  } else {
    fprintf(stderr, "A Unhandled flags %x\n", flags);
    return SQLITE_MISUSE;
  }

#ifdef TRACE
  fprintf(stderr, "A open Else %s\n", zName);
#endif
  return pVfs->xOpen(pVfs, zName, pFile, flags, pOutFlags);
}

/* 
 * fill callback args
 */
static callback_file *
fill_callback_args(sqlite3_file *sf, short type, void *zBuf, int iAmt, 
                   sqlite_int64 iOfst)
{
  callback_file *p = (callback_file *) sf;
  struct callback_args *a = p->sm;

#ifdef CHECK_PROTOCOL
  if(a==NULL) return NULL;
#endif

  pthread_mutex_lock(&a->mux);
  while( a->op & CB_OP_BUSY ) pthread_cond_wait(&a->cond, &a->mux);
  a->op = type << CB_OP_SHIFT | CB_OP_CALL;
  a->amount = iAmt;
  a->offset = iOfst;
  a->buf = zBuf;

  return p;
}

static int call_callback(callback_file *cf)
{
#ifdef CHECK_PROTOCOL
  if(cf==NULL) return SQLITE_PROTOCOL;
  else {
#endif
  unsigned int ret;
  struct callback_args *a = cf->sm;
//  pthread_mutex_lock(&a->mux); -- done in fill_callback_args

  // calling chicken to add the blocklist to the mailbox (read)
  C_interrupt_call(the_callback_callback, the_callback_arg_converter, a);
  // waiting for the call to complete
  do {
    pthread_cond_wait(&a->cond, &a->mux);
    ret = a->op;  
  } while ( !(ret & CB_OP_RETURN) );
  a->op = 0;
  pthread_mutex_unlock(&a->mux);
  return ret >> 2;
#ifdef CHECK_PROTOCOL
  }
#endif
}

/*
** Close an callback-file.
*/
static int callbackCloseNot(sqlite3_file *pFile)
{
  return SQLITE_OK;
}

static int callbackClose(sqlite3_file *sf){
  int rc;
#ifdef TRACE
  fprintf(stderr, "A close %p\n", sf);
#endif
  rc = call_callback(fill_callback_args(sf, CB_IO_TYPE_CLOSE, NULL, 0, 0));
#ifdef CHECK_PROTOCOL
  ((callback_file *)sf)->sm = NULL;
#endif
  return rc;
}

/*
** Read data from an callback-file.
*/

static int callbackReadNot(sqlite3_file *sf, void *zBuf,
                           int iAmt, sqlite_int64 iOfst)
{
#ifdef TRACE
  fprintf(stderr, "read not %p\n", sf);
#endif
  return SQLITE_IOERR;
}

static int callbackRead(sqlite3_file *sf, void *zBuf,
                        int iAmt, sqlite_int64 iOfst)
{
#ifdef TRACE
  fprintf(stderr, "cb read %p %p %d %ld\n", sf, zBuf, iAmt, (long int) iOfst);
#endif
  return call_callback(fill_callback_args(sf, CB_IO_TYPE_READ, zBuf, iAmt, iOfst));
}

/*
** Write data to an callback-file.
*/
static int callbackWriteNot(sqlite3_file *pFile, const void *zBuf,
                            int iAmt, sqlite_int64 iOfst) {
  return SQLITE_OK;
}

static int callbackWrite(
  sqlite3_file *sf,     // structure
  const void *zBuf,     // buffer with data
  int iAmt,             // amount of bytes to write
  sqlite_int64 iOfst    // offset of file to write
){
#ifdef TRACE
  fprintf(stderr, "cb write %p %p %d %ld\n", sf, zBuf, iAmt, (long int) iOfst);
#endif
  return call_callback(fill_callback_args(sf, CB_IO_TYPE_WRITE, (void*) zBuf, iAmt, iOfst));
}

/*
** Truncate an callback-file.
*/
static int callbackTruncateNot(sqlite3_file *pFile, sqlite_int64 size)
{
  return SQLITE_OK;
}

static int callbackTruncate(sqlite3_file *sf, sqlite_int64 size)
{
#ifdef TRACE
  fprintf(stderr, "Atruncate\n");
#endif
  return call_callback(fill_callback_args(sf, CB_IO_TYPE_TRUNC, NULL, 0, size));
}

/*
** Sync an callback-file.
*/
static int callbackSyncNot(sqlite3_file *pFile, int flags)
{
  return SQLITE_OK;
}

/*
** Return the current file-size of an callback-file.
*/
static int callbackFileSizeNot(sqlite3_file *pFile, sqlite_int64 *pSize)
{
 *pSize = 0;
  return SQLITE_OK;
}
static int callbackFileSize(sqlite3_file *sf, sqlite_int64 *pSize)
{
  callback_file *p = (callback_file *) sf;
  struct callback_args *a = p->sm;
  int rc;
#ifdef TRACE
  fprintf(stderr, "cb fileSize %p\n", sf);
#endif
  rc = call_callback(fill_callback_args(sf, CB_IO_TYPE_FSIZE, pSize, 0, 0));
#ifdef TRACE
  fprintf(stderr, "cb fileSize %p: %ld\n", sf, (long) a->offset);
#endif
  if(rc == SQLITE_OK) *pSize = a->offset;
  return rc;
}

/*
** Lock an callback-file.
*/
static int callbackLockNot(sqlite3_file *pFile, int eLock)
{
  return SQLITE_OK;
}

static int callbackLock(sqlite3_file *pFile, int eLock)
{
  callback_file *p = (callback_file *) pFile;
#ifdef TRACE
  fprintf(stderr, "Alock\n");
#endif
  return SQLITE_OK;
}

/*
** Unlock an callback-file.
*/
static int callbackUnlockNot(sqlite3_file *pFile, int eLock)
{
  return SQLITE_OK;
}
static int callbackUnlock(sqlite3_file *pFile, int eLock)
{
  callback_file *p = (callback_file *) pFile;
#ifdef TRACE
  fprintf(stderr, "Aunlock %s\n", p->zName);
#endif
  return SQLITE_OK;
}

/*
** Check if another file-handle holds a RESERVED lock on an callback-file.
*/
static int callbackCheckReservedLockNot(sqlite3_file *pFile, int *pResOut)
{
  return SQLITE_OK;
}

static int callbackCheckReservedLock(sqlite3_file *pFile, int *pResOut)
{
  callback_file *p = (callback_file *) pFile;
#ifdef TRACE
  fprintf(stderr, "cb check reserved lock\n");
#endif
  return SQLITE_OK;
}

/*
** File control method. For custom operations on an callback-file.
*/
static int callbackFileControl(sqlite3_file *pFile, int op, void *pArg)
{
  return SQLITE_NOTFOUND;
}

/*
** Return the sector-size in bytes for an callback-file.
*/
static int callbackSectorSizeNot(sqlite3_file *pFile)
{
  return 0;
}

static int callbackSectorSize(sqlite3_file *sf)
{
  callback_file *p = (callback_file *) sf;
  struct callback_args *a = p->sm;
  call_callback(fill_callback_args(sf, CB_IO_TYPE_BLKSZ, NULL, 0, 0));
#ifdef TRACE
  fprintf(stderr, "SectorSize %p %ld\n", sf, (long) a->offset);
#endif
  return a->offset;
}

/*
** Return the device characteristic flags supported by an callback-file.
*/
static int callbackDeviceCharacteristics(sqlite3_file *pFile)
{
  return SQLITE_IOCAP_ATOMIC | SQLITE_IOCAP_SAFE_APPEND;
}

/*
** Delete the file located at zPath. If the dirSync argument is true,
** ensure the file-system modifications are synced to disk before
** returning.
*/
static int callbackDelete(sqlite3_vfs *aVfs, const char *zPath, int dirSync)
{
  return SQLITE_OK;
}

/*
** Test for access permissions. Return true if the requested permission
** is available, or false otherwise.
*/
static int callbackAccess(
  sqlite3_vfs *aVfs,
  const char *zPath, 
  int flags, 
  int *pResOut
)
{
  int rc = pVfs->xAccess(pVfs, zPath, flags, pResOut);
#ifdef TRACE
  fprintf(stderr, "A access %s want %d got %d\n", zPath, flags, *pResOut);
#endif
  return rc;
}

/*
** Populate buffer zOut with the full canonical pathname corresponding
** to the pathname in zPath. zOut is guaranteed to point to a buffer
** of at least (CALLBACK_MAX_PATHNAME+1) bytes.
*/
static int callbackFullPathname(
  sqlite3_vfs *aVfs, 
  const char *zPath, 
  int nOut, 
  char *zOut
){
#ifdef TRACE
  fprintf(stderr, "cb fpn %s\n", zPath);
#endif
  return pVfs->xFullPathname(pVfs, zPath, nOut, zOut);
}

/*
** Open the dynamic library located at zPath and return a handle.
*/
static void *callbackDlOpen(sqlite3_vfs *aVfs, const char *zPath){
#ifdef TRACE
  fprintf(stderr, "Adlop\n");
#endif
  return pVfs->xDlOpen(pVfs, zPath);
}

/*
** Populate the buffer zErrMsg (size nByte bytes) with a human readable
** utf-8 string describing the most recent error encountered associated 
** with dynamic libraries.
*/
static void callbackDlError(sqlite3_vfs *aVfs, int nByte, char *zErrMsg){
#ifdef TRACE
  fprintf(stderr, "Adlerr\n");
#endif
  return pVfs->xDlError(pVfs, nByte, zErrMsg);
}

/*
** Return a pointer to the symbol zSymbol in the dynamic library pHandle.
*/
static void (*callbackDlSym(sqlite3_vfs *aVfs, void *p, const char *zSym))(void){
#ifdef TRACE
  fprintf(stderr, "Adlsy\n");
#endif
  return pVfs->xDlSym(pVfs, p, zSym);
}

/*
** Close the dynamic library handle pHandle.
*/
static void callbackDlClose(sqlite3_vfs *aVfs, void *pHandle){
#ifdef TRACE
  fprintf(stderr, "Adlclo\n");
#endif
  return pVfs->xDlClose(pVfs, pHandle);
}

/*
** Populate the buffer pointed to by zBufOut with nByte bytes of 
** random data.
*/
static int callbackRandomness(sqlite3_vfs *aVfs, int nByte, char *zBufOut){
#ifdef TRACE
  fprintf(stderr, "arand\n");
#endif
  return pVfs->xRandomness(pVfs, nByte, zBufOut);
}

/*
** Sleep for nMicro microseconds. Return the number of microseconds 
** actually slept.
*/
static int callbackSleep(sqlite3_vfs *aVfs, int nMicro){
#ifdef TRACE
  fprintf(stderr, "Aslee\n");
#endif
  return pVfs->xSleep(pVfs, nMicro);
}

/*
** Return the current time as a Julian Day number in *pTimeOut.
*/
static int callbackCurrentTime(sqlite3_vfs *pVfs, double *result){
#ifdef TRACE
  fprintf(stderr, "Act\n");
#endif
  *result=-1.0;
  return -1;
}

/*
** Initialising the wrapper vfs callback_vfs
*/

#define max(a,b) ((a) > (b) ? (a) : (b))

/* Include this to run sqlite3 from fixed memory
 *
 * REQUIRED: configure sqlite3 with --enable-threadsafe=yes
 */
static void ac_config_sqlite3() {
 if(sqlite3_config(SQLITE_CONFIG_MULTITHREAD) != SQLITE_OK)
    fprintf(stderr, "SQLITE3 config MULTITHREAD failed.\n");
 {
  size_t size=5000000;
  void* heap = malloc(size);
  if(heap==NULL)
    fprintf(stderr, "SQLITE3 Heap Allocation Failed \n");
  else if(sqlite3_config(SQLITE_CONFIG_HEAP, heap, size, sizeof(C_word))
     != SQLITE_OK) {
    fprintf(stderr, "SQLITE3 Heap Config Failed \n");
  }}
}

static
sqlite3_vfs *callback_sqlite3_vfs_init(void *cb, void *cbr) {
  /* ac_config_sqlite3(); */
#ifdef TRACE
  fprintf(stderr, "regring %s \n", callback_vfs.zName);
#endif
  pthread_mutex_init(&the_shared_memory_mux, NULL);
  pthread_cond_init(&the_shared_memory_cond, NULL);
  if(pVfs == NULL ) {
    pVfs = sqlite3_vfs_find(NULL); // fetch default vfs
    if( !pVfs ){
      return NULL;
    }
    callback_vfs.szOsFile = callback_vfs.szOsFile - sizeof(sqlite3_file) + pVfs->szOsFile;
    sqlite3_vfs_register(&callback_vfs, 0);
  }
  the_callback_callback = cb;
  the_callback_arg_converter = cbr;
#ifdef TRACE
  fprintf(stderr, "registered %s \n", callback_vfs.zName);
#endif
  return &callback_vfs;
}

EOF
))

(module
 sqlite3pth
 (;;
  sql-null sql-null? sql-not
  ;;
  sql-field sql-index
  sql-with-tupels%-fold-left
  sqlite3-prepare
  sqlite3-exec sqlite3-call-with-transaction sqlite3-call-test/set
  sql-close
  sqlite3-interrupt!
  sql-result?
  sql-value
  sql-connect
  sql-with-tupels

  sql-ref sql-fold
  sqlite3-statement-name
  sqlite3-open-restricted-ro
  sqlite3-statement-container
  sqlite3-database-prep-cache
  sqlite3-database-name
  sqlite3-changes
  sqlite3-statement?
  sqlite3-statement-raw-pointer
  sqlite3-database-open-statements
  sqlite3-error? sqlite3-error-code sqlite3-error-args
  sqlite3-error-db-locked?
  sqlite3-open sqlite3-close
  sqlite3-open-restricted
  make-sqlite3-statement
  ;;
  make-vfs
  ;;
  sqlite3-bugworkaround-reset-restrictions
  ;; debug aid
  sqlite3-debug-statements
  )

(import scheme)
(cond-expand
 (chicken-4
  (import scheme foreign
	  chicken ;; (except chicken add1 sub1 with-exception-handler condition?)
	  (except srfi-18 raise)
	  srfi-1 extras)
  (use srfi-1 srfi-34 pthreads llrb-tree))
 (else
  (import
   (chicken base)
   (chicken type)
   (chicken foreign)
   (chicken blob)
   (chicken fixnum)
   (chicken flonum)
   (chicken format)
   (except srfi-18 raise) srfi-34
   (only srfi-1 reverse!)
   (only (chicken time) current-milliseconds)
   (only miscmacros ensure)
   pthreads)))
;; (import util shrdprmtr)
(import (prefix llrb-tree llrb:))
(import (prefix llrb-string-table string-))

#;(define-syntax with-mutex
  (syntax-rules ()
    ((_ mux body ...)
     (handle-exceptions
      ex
      (begin (mutex-unlock! mux) (raise ex))
      (mutex-lock! mux)
      (let ((result (begin body ...)))
	(mutex-unlock! mux)
	result)))))

(define-syntax with-mutex
  (syntax-rules ()
    ((_ mux body ...)
     (guard (ex (else (mutex-unlock! mux) (raise ex)))
	    (mutex-lock! mux)
	    (let ((result (begin body ...)))
	      (mutex-unlock! mux)
	      result)))))

(define (make-string/uninit size)
  (##sys#allocate-vector size #t #f #f))

(define (logerr fmt . args)
  (apply format (current-error-port) fmt args))

(define-record sql-null-type)
(define sql-null-object (make-sql-null-type))
(define (sql-null) sql-null-object)
(define sql-null? sql-null-type?)

(define (sql-not o)
  (if (sql-null? o) o (not o)))

;;(include "typedefs.scm")
(define-type :sql-result: vector)

;; (define sqlite3-debug-statements (make-shared-parameter #f))

(define sqlite3-debug-statements
  (let ((v #f))
    (lambda args
      (if (pair? args)
	  (let ((old v)) (set! v (car args)) old)
	  v))))

(define new-gc-root
  (foreign-lambda*
   c-pointer ()
   "C_GC_ROOT *r=CHICKEN_new_gc_root();"
   "C_return(r);"))

(define make-gc-root
  (foreign-lambda*
   c-pointer ((scheme-object obj))
   "C_GC_ROOT *r=CHICKEN_new_gc_root();"
   "CHICKEN_gc_root_set(r, obj);"
   "C_return(r);"))

(define delete-gc-root
  (foreign-lambda*
   void ((c-pointer r))
   "CHICKEN_gc_root_set(r, C_SCHEME_FALSE);"
   "CHICKEN_delete_gc_root(r);"))

(define set-gc-root!
  (foreign-lambda*
   void ((c-pointer r) (scheme-object obj))
   "CHICKEN_gc_root_set((C_GC_ROOT *) r, obj);"))

(define *the-db-drivers* '())

#;(define-condition-type &sqlite3-error &error sqlite3-error?
  (code sqlite3-error-code)
  (args sqlite3-error-args))

(define-record sqlite3-error code args)
(define-record-printer (sqlite3-error x out)
  (format out "<sqlite3-error ~a ~a>"  (sqlite3-error-code x) (sqlite3-error-args x)))

(define (raise-no-db connection msg)
  (raise #;(condition (&message (message (format "No sqlite3 connection ~a for ~a" connection msg))))
	 (make-sqlite3-error #f (format "No sqlite3 connection ~a for ~a" connection msg))))

(define (sqlite3-raise-closed db)
  (raise #;(condition (&message (message (format "sqlite3 connection ~a closed"
					       (sqlite3-database-name db)))))
	 (make-sqlite3-error #f (format "sqlite3 connection ~a closed"
					(sqlite3-database-name db)))))

(define (sql-connect driver db host user pass)
  (let ((entry (assoc driver *the-db-drivers*)))
    (if entry
	((cdr entry) db host user pass)
	(error (string-append "sql-connect unsupported driver '"
			      driver
			      "' requested.")))))
(define (sql-close obj)
  ((cond
    ((sqlite3-database? obj) sqlite3-close)
    (else (raise-no-db obj 'sql-close)))
   obj))

(define sql-result? vector?)

(define (sql-value result row field)
  ((cond
    ((sql-result? result) sqlite3-value)
    (else (raise
	   #;(condition (&message (message (format "sql-value not a sqlite3 result ~a" result))))
	   (make-sqlite3-error #f (format "sql-value not a sqlite3 result ~a" result)))))
   result row field))

(define (sql-field result field)
  ((cond
    ((sql-result? result) sqlite3-field)
    (else (raise
	   #;(condition (&message (message (format "sql-field not a sqlite3 result ~a" result))))
	   (make-sqlite3-error #f (format "sql-field not a sqlite3 result ~a" result)))))
   result field))

(define (sql-with-tupels connection query proc)
  ((cond
    ((sqlite3-database? connection) sqlite3-with-tupels)
    (else (raise-no-db connection query)))
   connection query proc))

;; WARNING: sql-index, sql-field and sql-value are experimental.

(: sql-index (:sql-result: string --> (or false fixnum)))
(define (sql-index self field)
  (and (fx> (vector-length self) 0)
       (vassoc field (vector-ref self 0))))

(: sqlite3-field (:sql-result: fixnum --> string))
(define (sqlite3-field self field)
  (let* ((cv (vector-ref self 0))
	 (cn (vector-length cv)))
    (if (fx>= field cn) (error (format "sql-field column ~a out of range [0,~a)" field cn)))
    (vector-ref cv field)))

(: sqlite3-value (:sql-result: fixnum (or fixnum string symbol) --> *))
(define (sqlite3-value self row field)
  (let ((rn (vector-length self))
	(ri (add1 row)))
    (if (fx>= ri rn) (error (format "sql-ref row ~a out of range [0,~a)" ri rn)))
    (let* ((rv (vector-ref self ri))
	   (cn (vector-length rv)))
      (let ((ci (or (cond
		     ((integer? field) field)
		     ((string? field) (sql-index self field))
		     ((symbol? field) (sql-index self (symbol->string field)))
		     (else (error (format "sql-value bad index type ~s" field))))
		    (error (format "no field ~a in ~a" field
				   (vector-ref self 0))))))
	(if (fx>= ci cn) (error (format "sql-ref column ~a out of range ~a" ci cn)))
	(vector-ref rv ci)))))

(: sql-ref
   (:sql-result: (or boolean fixnum) (or boolean fixnum string symbol) --> *))
(define (sql-ref self row field)
  (if (not (sql-result? self)) (error (format "sql-ref not a sql result ~a" self)))
  (cond
   ((and row field) (sql-value self row field))
   (field (sql-index self field))
   (row (vector-length (vector-ref self 0)))
   (else (sub1 (vector-length self)))))

(: sql-fold (:sql-result: (procedure ((procedure (fixnum) *) *) *) * -> *))
(define sql-fold
  (letrec ((loop (lambda (kons knil len result i)
                   (if (eqv? i len)
                       knil
                       (loop kons
                             (kons
			      (lambda (x) (sql-value result i x))
			      knil)
                             len result (add1 i))))))
    (lambda (self kons knil)
      (loop kons knil (sub1 (vector-length self)) self 0))))

(define (one-shot-sql-tupels%-fold-left db query setup-seeds fold-function seeds)
  (define (range n)
    (let loop ((i 0))
      (if (eqv? i n) '() (cons i (loop (add1 i))))))
  ;; TODO fix the mxsql-driver to actually return the value!
  (sql-with-tupels
   db query
   (lambda (result rows cols)
     (if (eqv? rows 0)
         (apply values (append seeds (setup-seeds result rows cols)))
         (let ((cols (range cols)))
           (let loop ((seeds (append seeds (setup-seeds result rows cols)))
                      (row 0))
             (if (eqv? row rows)
                 (apply values seeds)
                 (receive (proceed . seeds)
                          (apply fold-function
                                 (map (lambda (field)
                                        (sql-value result row field))
                                      cols)
                                 seeds)
                          (if proceed
                              (loop seeds (add1 row))
                              (apply values seeds))))))))))

(define (sql-with-tupels%-fold-left db query setup-seeds fold-function seed . seeds)
  (one-shot-sql-tupels%-fold-left db query setup-seeds fold-function (cons seed seeds)))

(: sqlite3-database? (* --> boolean : (struct <sqlite3-database>)))
(: sqlite3-database-name ((struct <sqlite3-database>) --> *))
(define-record-type <sqlite3-database>
  (%make-sqlite3-database raw-pointer callback-args callback open-statemets prep-cache mux name)
  sqlite3-database?
  (raw-pointer sqlite3-database-raw-pointer set-sqlite3-database-raw-pointer!)
  (callback-args sqlite3-database-callback-args set-sqlite3-database-callback-args!)
  (callback sqlite3-database-callback)
  (open-statemets sqlite3-database-open-statements set-sqlite3-database-open-statement!)
  (prep-cache sqlite3-database-prep-cache)
  (mux sqlite3-database-mutex)
  (name sqlite3-database-name))

(define-syntax make-open-statement (syntax-rules () ((_) #f)))

(define-inline (make-prep-cache) (string-make-table))

(define-inline (prep-cache-ref c k t) (string-table-ref c k t))
(define-inline (prep-cache-ref/default c k d) (string-table-ref/default c k d))
(define-inline (prep-cache-set! c k v) (string-table-set! c k v))
(define-inline (prep-cache-for-each c p) (string-table-for-each c p))
(define-inline (prep-cache-clear! db)
  #;(hash-table-clear! (sqlite3-database-prep-cache db))
  #f)


(define (sqlite3-finaliser-close db)
  (when (sqlite3-database-raw-pointer db)
	(logerr "WARNING (deprecated use): sqlite db closed by finaliser - which is being obsoleted ~a\n" (sqlite3-database-name db))
	(sqlite3-close db)))

(define (make-sqlite3-database raw-pointer callback-args callback open-statemets prep-cache name)
  (let ((r (%make-sqlite3-database raw-pointer callback-args callback open-statemets prep-cache (make-mutex name) name)))
;;    (set-finalizer! r sqlite3-finaliser-close)
    r))

(define (sqlite3-with-tupels self query proc)
  ;; FIXME we need to write a per connection thread.
  (let* ((result ; (sqlite3-async-exec self query)
		(sqlite3-exec self query))
	 (rows (vector-length result)))
    (if (eqv? rows 0)
	(proc result 0 0)
	(proc result (sub1 rows) (vector-length (vector-ref result 0))))))

(define (vassoc val vec)
  (do ((i 0 (add1 i)))
      ((or (eqv? i (vector-length vec))
	   (equal? val (vector-ref vec i)))
       (and (fx< i (vector-length vec)) i))))


(define-foreign-variable SQLITE_OTHER int "SQLITE_OTHER")
(define-foreign-variable SQLITE_OK int "SQLITE_OK")
(define-foreign-variable SQLITE_ERROR int "SQLITE_ERROR")
(define-foreign-variable SQLITE_INTERNAL int "SQLITE_INTERNAL")
(define-foreign-variable SQLITE_PERM int "SQLITE_PERM")
(define-foreign-variable SQLITE_ABORT int "SQLITE_ABORT")
(define-foreign-variable SQLITE_BUSY int "SQLITE_BUSY")
(define-foreign-variable SQLITE_LOCKED int "SQLITE_LOCKED")
(define-foreign-variable SQLITE_NOMEM int "SQLITE_NOMEM")
(define-foreign-variable SQLITE_READONLY int "SQLITE_READONLY")
(define-foreign-variable SQLITE_INTERRUPT int "SQLITE_INTERRUPT")
(define-foreign-variable SQLITE_IOERR int "SQLITE_IOERR")
(define-foreign-variable SQLITE_IOERR_SHORT_READ int "SQLITE_IOERR_SHORT_READ")
(define-foreign-variable SQLITE_CORRUPT int "SQLITE_CORRUPT")
(define-foreign-variable SQLITE_NOTFOUND int "SQLITE_NOTFOUND")
(define-foreign-variable SQLITE_FULL int "SQLITE_FULL")
(define-foreign-variable SQLITE_CANTOPEN int "SQLITE_CANTOPEN")
(define-foreign-variable SQLITE_PROTOCOL int "SQLITE_PROTOCOL")
(define-foreign-variable SQLITE_EMPTY int "SQLITE_EMPTY")
(define-foreign-variable SQLITE_SCHEMA int "SQLITE_SCHEMA")
(define-foreign-variable SQLITE_TOOBIG int "SQLITE_TOOBIG")
(define-foreign-variable SQLITE_CONSTRAINT int "SQLITE_CONSTRAINT")
(define-foreign-variable SQLITE_MISMATCH int "SQLITE_MISMATCH")
(define-foreign-variable SQLITE_MISUSE int "SQLITE_MISUSE")
(define-foreign-variable SQLITE_NOLFS int "SQLITE_NOLFS")
(define-foreign-variable SQLITE_AUTH int "SQLITE_AUTH")
(define-foreign-variable SQLITE_ROW int "SQLITE_ROW")
(define-foreign-variable SQLITE_DONE int "SQLITE_DONE")

(define-foreign-type <raw-sqlite3-database> (nonnull-c-pointer "struct sqlite3_db"))

(define (sqlite3-bugworkaround-reset-restrictions db)
  ((foreign-lambda* void ((<raw-sqlite3-database> a)) "sqlite3_set_authorizer_unrestricted(a->cnx);")
   (sqlite3-database-raw-pointer db)))

(define-foreign-type <raw-sqlite3-statement> (c-pointer "sqlite3_stmt"))

(: sqlite3-statement? (* --> boolean : (struct <sqlite3-statement>)))

(define-record-type <sqlite3-statement>
  (make-sqlite3-statement raw-pointer container name)
  sqlite3-statement?
  (raw-pointer sqlite3-statement-raw-pointer)
  (container sqlite3-statement-container %set-sqlite3-statement-container!)
  (name sqlite3-statement-name)
  )

(define-inline (sqlite3-statement-valid? db stmt)
  (eq? (sqlite3-statement-container stmt) db))

(define-inline (sqlite3-run-fn root param fn values)
  ((##sys#slot root 1) param fn values))

(define sqlite3-error-message/raw
  (foreign-lambda*
   c-string ((<raw-sqlite3-database> db))
   "C_return(db ? sqlite3_errmsg(db->cnx) : \"connection lost\");"))

(define (sqlite3-error-message d)
  (if (sqlite3-database-raw-pointer d)
      (sqlite3-error-message/raw (sqlite3-database-raw-pointer d))
      (string-append "connection lost to " (sqlite3-database-name d))))

(define (sqlite3-error-db-locked? obj)
  (and (sqlite3-error? obj)
       (eq? (sqlite3-error-code obj) SQLITE_BUSY)))

(define-foreign-type <sqlite3-callback-args> (c-pointer "struct callback_args"))

(define alloc-callback
  (foreign-lambda*
   <sqlite3-callback-args>
   ((integer size)
    (scheme-object db))
   #<<EOF
struct callback_args *a=L_malloc(sizeof(struct callback_args) + size);
a->op = 0;
pthread_mutex_init(&a->mux, NULL);  
pthread_cond_init(&a->cond, NULL);  
a->size = size;
a->ref = CHICKEN_new_gc_root();
CHICKEN_gc_root_set(a->ref, db);
C_return(a);
EOF
))

(define-foreign-type <sqlite3-open-args> (nonnull-c-pointer "struct open_args"))

(define open-args
  (foreign-lambda*
   <sqlite3-open-args>
   ((scheme-object dbn)
    (integer dbnlen)
    (integer setup)
    (scheme-object vfs)
    (integer vfslen)
    (<sqlite3-callback-args> sm))
   #<<EOF
struct open_args *a=L_malloc(sizeof(struct open_args) + dbnlen + vfslen + 2);
a->cnx = NULL;
strncpy(a->dbn, C_c_string(dbn), dbnlen);
a->dbn[dbnlen]='\0';
a->setup = setup;
if( vfs == C_SCHEME_FALSE ) {
  a->vfs=NULL;
  a->sm=NULL;
} else {
  a->sm=sm;
  a->vfs = a->dbn+dbnlen+1;
  strncpy(a->vfs, C_c_string(vfs), vfslen);
  a->vfs[vfslen]='\0';
}
C_return(a);
EOF
))

(define free-callback-args
  (foreign-lambda*
   void ((<sqlite3-callback-args> a))
#|
 if: we want to be sure that the other side is done with the callback,
 we lock/unlock the mutex once.
 this *seems* to be helpful, at least with rscheme (which is more prone
 to race conditions, thus only ahead when it comes to such errors).
|#
   "pthread_mutex_lock(&a->mux);"
   "while(a->op & CB_OP_BUSY) pthread_cond_wait(&a->cond, &a->mux);"
   "pthread_mutex_unlock(&a->mux);"
   ;; normal code needs only the rest
   "pthread_mutex_destroy(&a->mux);"
   "pthread_cond_destroy(&a->cond);"
   "CHICKEN_gc_root_set(a->ref, C_SCHEME_FALSE);"
   "CHICKEN_delete_gc_root(a->ref);"
   "L_free(a);"))

(define sqlite3-start-open
  (foreign-lambda* void ((<sqlite3-open-args> s) (nonnull-c-pointer callback))
		   "start_asynchronous_request(pthread_sqlite3_open, s, callback);"))

(define (make-callback-interface obj)
  (alloc-callback 0 obj))

(define (sqlite3-open* dbn setup vfs sm)
  (let ((root (let ((mux (make-mutex 'sqlite3))
		    (cv (make-condition-variable 'sqlite3))
		    (result #f)
		    (root (new-gc-root)))
		#;(let ((cb (lambda (x)
			    (mutex-lock! mux)
			    (set! result x)
			    (mutex-unlock! mux)
			    (condition-variable-signal! cv)))
		      (req (lambda (param fn)
			     (mutex-lock! mux)
			     (set! result mux)
			     (semaphore-wait pthread-pool-load)
			     (fn param root)
			     (semaphore-signal pthread-pool-load)
			     (let loop ()
			       (mutex-unlock! mux cv)
			       (mutex-lock! mux)
			       (if (eq? result mux) (loop)
				   (begin
				     (mutex-unlock! mux)
				     (values result param)))))))
		  (set-gc-root! root cb)
		  (vector root req))

		(let ((cb (lambda (x)
			    (set! result x)
			    (mutex-unlock! mux)))
		      (req (lambda (param fn values)
			     (set! result mux)
			     ;; (semaphore-wait pthread-pool-load)
			     (fn param root)
			     ;; (semaphore-signal pthread-pool-load)
			     (mutex-lock! mux #f #f)
			     (values result param))))
		  (mutex-lock! mux #f #f)
		  (set-gc-root! root cb)
		  (vector root req))


)))
    (sqlite3-run-fn
     root
     (open-args dbn (string-length dbn)
		setup
		vfs (if vfs (string-length vfs) 0)
		sm)
     sqlite3-start-open
     ;; process reply
     (lambda (result param)
       (if (eqv? result SQLITE_OK)
	   (values
	    root
	    ((foreign-lambda*
	      <raw-sqlite3-database>
	      ((<sqlite3-open-args> a)
	       (integer additional))
	      ;;"sqlite3 *cnx = a->cnx; L_free(a); C_return(cnx);"
	      "struct sqlite3_db *db = L_malloc(sizeof(struct sqlite3_db));"
	      "db->cnx = a->cnx;"
	      "db->bufsize = sizeof(struct open_args) + additional;"
	      "db->buf = a;"
	      "C_return(db);"
	      )
	     param
	     (fx+ (string-length dbn) (if vfs (string-length vfs) 0))))
	   (begin
	     ((foreign-lambda* void ((<sqlite3-open-args> a)) "L_free(a);") param)
	     (delete-gc-root (vector-ref root 0))
	     (if sm (free-callback-args sm))
	     (raise #;(condition (&sqlite3-error (code result) (args (list 'open dbn))))
		    (make-sqlite3-error result (list 'open dbn)))))))))

(: sqlite3-open (string --> (struct <sqlite3-database>)))
(define (sqlite3-open dbn)
  (receive
   (cb raw-db) (sqlite3-open* dbn 1 #f #f)
   (make-sqlite3-database raw-db #f cb (make-open-statement) (make-prep-cache) dbn)))

(: sqlite3-open-restricted
   (string #!optional string vector --> (struct <sqlite3-database>)))
(define (sqlite3-open-restricted dbn . vfs)
  (if (pair? vfs)
      (let ((sm (make-callback-interface (cadr vfs))))
	(receive (cb raw-db) (sqlite3-open* dbn 2 (car vfs) sm)
		 (make-sqlite3-database
		  raw-db sm cb (make-open-statement) (make-prep-cache) dbn)))
      (receive (cb raw-db) (sqlite3-open* dbn 2 #f #f)
	       (make-sqlite3-database
		raw-db #f cb (make-open-statement) (make-prep-cache) dbn))))

(: sqlite3-open-restricted-ro
   (string #!optional string vector --> (struct <sqlite3-database>)))
(define (sqlite3-open-restricted-ro dbn . vfs)
  (if (pair? vfs)
      (let ((sm (make-callback-interface (cadr vfs))))
	(receive (cb raw-db) (sqlite3-open* dbn 3 (car vfs) sm)
		 (make-sqlite3-database
		  raw-db sm cb (make-open-statement) (make-prep-cache) dbn)))
      (receive (cb raw-db) (sqlite3-open* dbn 3 #f #f)
	       (make-sqlite3-database
		raw-db #f cb (make-open-statement) (make-prep-cache) dbn))))

(define sqlite3-start-close
  (foreign-lambda* void ((<raw-sqlite3-database> s) (nonnull-c-pointer callback))
		   "start_asynchronous_request((C_pthread_request_function_t) pthread_sqlite3_close, s, callback);"))


(: sqlite3-close ((struct <sqlite3-database>) -> . *))
(define (sqlite3-close db)
  (if (thread? (mutex-state (sqlite3-database-mutex db))) (sqlite3-interrupt! db))
  (with-mutex
   (sqlite3-database-mutex db)
   (if (sqlite3-database-raw-pointer db)
       (let ((raw (sqlite3-database-raw-pointer db)))
	 (prep-cache-for-each
	  (sqlite3-database-prep-cache db)
	  (lambda (k stmt)
	    (sqlite3-finalize db (sqlite3-statement-raw-pointer stmt))
	    (%set-sqlite3-statement-container! stmt #f)))
	 (prep-cache-clear! db)
	 (set-sqlite3-database-raw-pointer! db #f)
	 (sqlite3-run-fn
	  (sqlite3-database-callback db) raw sqlite3-start-close
	  (lambda (rc dbo)
	    (delete-gc-root (vector-ref (sqlite3-database-callback db) 0))
	    (and-let* ((sm (sqlite3-database-callback-args db)))
		      (set-sqlite3-database-callback-args! db #f)
		      (free-callback-args sm))
	    (if (not (eqv? rc SQLITE_OK))
		(raise #;(condition
			(&sqlite3-error
			 (code rc)
			 (args (list 'close (sqlite3-database-name db))))
			(&message (message (sqlite3-error-message/raw raw))))
		       (make-sqlite3-error
			rc
			(list 'close (sqlite3-database-name db) (sqlite3-error-message/raw raw)))))))))))

(: sqlite3-interrupt! ((struct <sqlite3-database>) -> * #;boolean))
(define (sqlite3-interrupt! db)
  (and-let* ((raw (sqlite3-database-raw-pointer db)))
	    ((foreign-lambda* void ((<raw-sqlite3-database> a)) "sqlite3_interrupt(a->cnx);") raw)))

(define sqlite3-changes
  (foreign-lambda*
   integer ((<raw-sqlite3-database> db))
   "C_return(sqlite3_changes(db->cnx));" ))

(define sqlite3-finalize*
  (foreign-lambda integer "sqlite3_finalize" <raw-sqlite3-statement>))

(define (sqlite3-finalize db stmt)
  (let ((v (sqlite3-finalize* stmt)))
    (or (eqv? v SQLITE_OK)
	(raise #;(condition (&message (message (sqlite3-error-message db))))
	       (make-sqlite3-error v (sqlite3-error-message db))))))

(define-foreign-type <sqlite3-prepare-args> (nonnull-c-pointer "struct prepare_args"))

(define prepare-args
  (foreign-lambda*
   <sqlite3-prepare-args>
   ((<raw-sqlite3-database> db)
    (scheme-object sql)
    (integer sqllen)
    (integer offset))
   "size_t bufsize = sizeof(struct prepare_args) + sqllen;"
   "if(db->bufsize < bufsize) { L_free(db->buf); db->buf = L_malloc(bufsize); db->bufsize = bufsize; }"
   "struct prepare_args *a=db->buf;"
   "a->stmt = NULL;"
   "a->db = db->cnx;"
   "strncpy(a->sql,C_c_string(sql), sqllen); a->sql[sqllen]='\\0';"
   "a->sql_len = sqllen;"
   "a->offset = offset;"
   "C_return(a);"
   ))

(define sqlite3-start-prepare
  (foreign-lambda* void ((<sqlite3-prepare-args> s) (nonnull-c-pointer callback))
		   "start_asynchronous_request(pthread_sqlite3_prepare, s, callback);"))

(define (sqlite3-prepare* db sql offset continue)
  (if (sqlite3-debug-statements)
      (logerr "~a: \"~a\" (~a)\n" (sqlite3-database-name db) sql offset))
  (sqlite3-run-fn
   (sqlite3-database-callback db)
   (prepare-args (sqlite3-database-raw-pointer db) sql (string-length sql) offset)
   sqlite3-start-prepare
   (lambda (rc param)
     (if (eqv? rc SQLITE_OK)
	 (let ((stmt ((foreign-lambda*
		       <raw-sqlite3-statement>
		       ((<sqlite3-prepare-args> a))
		       "C_return(a->stmt);") param))
	       (n ((foreign-lambda*
		    integer
		    ((<sqlite3-prepare-args> a))
		    "C_return(a->tail);") param)))
	   ;; ((foreign-lambda* void ((<sqlite3-prepare-args> a)) "L_free(a);") param)
	   (continue stmt n))
	 (begin
	   ;; ((foreign-lambda*  void ((<sqlite3-prepare-args> a)) "L_free(a);") param)
	   (raise #;(condition
		   (&sqlite3-error
		    (code rc)
		    (args (list 'prepare sql)))
		   (&message (message (sqlite3-error-message db))))
		  (make-sqlite3-error rc (sqlite3-error-message db))))))))

(define-inline (sqlite3-prepare/while-locked db sql)
  (or (prep-cache-ref/default (sqlite3-database-prep-cache db) sql #f)
      (sqlite3-prepare*
       db sql 0
       (lambda (raw n)
	 (and raw
	      (let ((stmt (make-sqlite3-statement raw db sql)))
		(prep-cache-set! (sqlite3-database-prep-cache db) sql stmt)
		stmt))))))

(: sqlite3-prepare ((struct <sqlite3-database>) string --> (struct <sqlite3-statement>)))
(define (sqlite3-prepare db sql)
  (ensure string? sql)
  (or (prep-cache-ref/default (sqlite3-database-prep-cache db) sql #f)
      (with-mutex
       (sqlite3-database-mutex db)
       (sqlite3-prepare/while-locked db sql))))

(define sqlite3-db-handle
  (foreign-lambda void "sqlite3_db_handle" <raw-sqlite3-statement>))

(define sqlite3-start-step
  (foreign-lambda* void ((<raw-sqlite3-statement> s) (nonnull-c-pointer callback))
		   "start_asynchronous_request((C_pthread_request_function_t)sqlite3_step, s, callback);"))

(define sqlite3-column-count
  (foreign-lambda integer "sqlite3_column_count" <raw-sqlite3-statement>))

(define sqlite3-column-name
  (foreign-lambda c-string "sqlite3_column_name" <raw-sqlite3-statement> integer))

#;(define (sqlite3-columns st)
  (let ((n (sqlite3-column-count st)))
    (let loop ((i 0))
      (if (eqv? i n) '()
	  (cons (sqlite3-column-name st i) (loop (add1 i)))))))

(define (sqlite3-columns st)
  (let* ((n (sqlite3-column-count st))
	 (result (##sys#allocate-vector n #f #f #f)))
    (do ((i 0 (add1 i)))
	((eq? i n) result)
      (##sys#setslot result i (sqlite3-column-name st i)))))

;;;
;;;  Return a list of lists
;;;

(define sqlite3-empty-result '#(#()))

(define (abort-sqlite3-error loc code db stmt . more)
  (make-sqlite3-error code (cons (cons loc more) (sqlite3-error-message db))))

(define (bind! db stmt i v)
  ;;(check-statement 'bind! stmt)
  ;;(check-cardinal-integer 'bind! i)
  (cond
   ;; SQLITE_STATIC /*SQLITE_TRANSIENT*/
   ;;
   ;; Since the calling chicken thread will block while the query is
   ;; running, disable-interrupts can not ensure the data does not
   ;; move.  You should use SQLITE_STATIC if your garbage collection
   ;; is non-moving.
   ((blob? v)
    (let ((rc ((foreign-lambda* integer
				((<raw-sqlite3-statement> stmt) (int i) (scheme-pointer v) (int n))
				"return(sqlite3_bind_blob(stmt, i, v, n, /*SQLITE_STATIC*/ SQLITE_TRANSIENT));")
	       stmt (fx+ i 1) v (blob-size v))))
      (if (eqv? rc SQLITE_OK) #f (abort-sqlite3-error 'bind! rc db stmt i v))))
   ((or (and (fixnum? v) v) (and (boolean? v) (if v 1 0)))
    => (lambda (v)
	 (let ((rc ((foreign-lambda integer "sqlite3_bind_int"
				    <raw-sqlite3-statement> int int)
		    stmt (fx+ i 1) v)))
	   (if (eqv? rc SQLITE_OK) #f (abort-sqlite3-error 'bind! rc db stmt i v)))))
   ((real? v)
    (let ((rc ((foreign-lambda integer "sqlite3_bind_double"
			    <raw-sqlite3-statement> int double)
	       stmt (fx+ i 1) v)))
      (if (eqv? rc SQLITE_OK) #f (abort-sqlite3-error 'bind! rc db stmt i v))))
   ((string? v)
    (let ((rc ((foreign-lambda* integer
				((<raw-sqlite3-statement> stmt) (int i) (scheme-pointer v) (int n))
				"return(sqlite3_bind_text(stmt, i, v, n, /*SQLITE_STATIC*/ SQLITE_TRANSIENT));")
	       stmt (fx+ i 1) v (string-length v))))
      (if (eqv? rc SQLITE_OK) #f (abort-sqlite3-error 'bind! rc db stmt i v))))
   ((sql-null? v)
    (let ((rc ((foreign-lambda integer "sqlite3_bind_null" <raw-sqlite3-statement> int)
	       stmt (fx+ i 1))))
      (if (eqv? rc SQLITE_OK) #f (abort-sqlite3-error 'bind! rc db stmt i v))))
   (else
    (abort-sqlite3-error "bind! blob, number, boolean, string or sql-null" #f db stmt i v))))

(define (sqlite3-bind! db stmt args)
  (let loop ((i 0) (args args))
    (if (null? args) #f
	(let ((rc (bind! db stmt i (car args))))
	  (if rc rc (loop (add1 i) (cdr args)))))))

(define-foreign-variable SQLITE_INTEGER int "SQLITE_INTEGER")
(define-foreign-variable SQLITE_FLOAT int "SQLITE_FLOAT")
(define-foreign-variable SQLITE_NULL int "SQLITE_NULL")
(define-foreign-variable SQLITE_TEXT int "SQLITE_TEXT")
(define-foreign-variable SQLITE_BLOB int "SQLITE_BLOB")

(define sqlite3-column-type
  (foreign-lambda int "sqlite3_column_type" <raw-sqlite3-statement> integer))

(define sqlite3-column-int64
  (foreign-lambda integer64 "sqlite3_column_int64" <raw-sqlite3-statement> integer))

(define sqlite3-column-float
  (foreign-lambda double "sqlite3_column_double" <raw-sqlite3-statement> integer))

(define sqlite3-column-text
  (foreign-lambda c-string "sqlite3_column_text" <raw-sqlite3-statement> integer))

(define sqlite3-column-string-get
  (foreign-lambda*
   scheme-object ((scheme-object buf) (c-pointer src) (integer n))
   "if(n>0) {"
   "C_memcpy(C_c_string(buf), src, n);"
   "} C_return(buf);"))

(define %copy! (foreign-lambda c-pointer "C_memcpy" scheme-pointer c-pointer int))

(define sqlite3-column-blob0
  (foreign-lambda c-pointer "sqlite3_column_blob" <raw-sqlite3-statement> integer))

(define sqlite3-column-bytes
  (foreign-lambda integer "sqlite3_column_bytes" <raw-sqlite3-statement> integer))

(define (sqlite3-column-string stmt i)
  (let* ((src (sqlite3-column-blob0 stmt i))
	 (n (sqlite3-column-bytes stmt i))
	 (str (make-string/uninit n)))
    (sqlite3-column-string-get str src n)))

(define (sqlite3-column-blob stmt i)
  (let* ((src (sqlite3-column-blob0 stmt i))
	 (n (sqlite3-column-bytes stmt i))
	 (b (make-blob n)))
    (%copy! b src n)
    b))

(define (sqlite3-column-null x i) #f)

#;(define (sqlite3-values st)
  (let ((n (sqlite3-column-count st)))
    (let loop ((i 0))
      (if (eqv? i n) '()
	  (cons (let ((type (sqlite3-column-type st i)))
		  (cond
		    ((eq? type SQLITE_INTEGER) (sqlite3-column-int64 st i))
		    ((eq? type SQLITE_FLOAT) (sqlite3-column-float st i))
		    ((eq? type SQLITE_NULL) #f)
		    ((eq? type SQLITE_TEXT) (sqlite3-column-blob st i))
		    ((eq? type SQLITE_BLOB) (sqlite3-column-blob st i))
		    (else (error "Wrong sqlite3 column type"))))
		(loop (add1 i)))))))

(define (sqlite3-values st)
  (let* ((n (sqlite3-column-count st))
	 (result (##sys#allocate-vector n #f #f #f)))
    (do ((i 0 (add1 i)))
	((eq? i n) result)
	(##sys#setslot
	 result i
	 (let ((type (sqlite3-column-type st i)))
	   (cond
	    ((eq? type SQLITE_INTEGER) (sqlite3-column-int64 st i))
	    ((eq? type SQLITE_FLOAT) (sqlite3-column-float st i))
	    ((eq? type SQLITE_NULL) #f)
	    ((eq? type SQLITE_TEXT) (sqlite3-column-string st i))
	    ((eq? type SQLITE_BLOB) (sqlite3-column-blob st i))
	    (else (error "Wrong sqlite3 column type"))))))))

(define-inline (sqlite3-for-each db s fn)
  (do ((exit #f))
      (exit #t)
    (sqlite3-run-fn
     (sqlite3-database-callback db) s sqlite3-start-step
     (lambda (rc s) 
       (cond
	((eqv? rc SQLITE_ROW) (fn (sqlite3-values s)))
	((eqv? rc SQLITE_DONE) (set! exit #t) #f)
	(else (raise #;(condition
		      (&sqlite3-error
		       (code rc)
		       (args (list 'step)))
		      (&message (message (sqlite3-error-message db))))
		     (make-sqlite3-error rc (sqlite3-error-message db)))))))))

(define (raise-sqlite3-db-closed db stmt)
  (raise #;(make-condition &sqlite3-error 'code 1 'error (list db stmt))
	 (make-sqlite3-error 1 (list db stmt))))

(define (sqlite3-exec** db stmt args)
  (let loop ((n 0)
	     (r0 sqlite3-empty-result))
    (if (fx< n (string-length stmt))
	(sqlite3-prepare*
	 db stmt n
	 (lambda (p n)
	   (if p
	       (let ((r '())
		     (tm0 #f) (tm1 #f))
		 ;;
		 (if (pair? args)
		     (and-let* ((exn (sqlite3-bind! db p args)))
			       (sqlite3-finalize db p)
			       (raise exn)))
		 (set-sqlite3-database-open-statement! db p) ;; register for exception handler
		 ;;
		 (if (sqlite3-debug-statements) (set! tm0 (current-milliseconds)))
		 (sqlite3-for-each
		  db p
		  (lambda (row)
		    (set! r (cons row r))))
		 (if tm0 (set! tm1 (current-milliseconds)))
		 (let ((r0 (list->vector
			    (cons
			     (sqlite3-columns p)
			     (reverse! r)))))
		   (sqlite3-finalize db p)
		   (set-sqlite3-database-open-statement! db #f)
		   (if (and tm0 tm1)
		       (let ((d (fp- tm1 tm0))
			     (n (sub1 (vector-length r0))))
			 (logerr "~a: ~a results in ~a ms (~a)\n"
				 (sqlite3-database-name db) n d
				 (and (> n 0) (fp/ d (exact->inexact n))))))
		   (loop n r0)))
	       r0)))
	r0)))

;; Reset an existing statement to process it again
(define (reset! stmt args)
  (let ((rc ((foreign-lambda integer "sqlite3_reset" <raw-sqlite3-statement>) (sqlite3-statement-raw-pointer stmt))))
    (if (eqv? rc SQLITE_OK) #t
	(raise (abort-sqlite3-error 'sqlite3:reset! rc (sqlite3-statement-container stmt) stmt args)))))

(define (sqlite3-exec/prepared db stmt args)
  (if (sqlite3-debug-statements)
      (logerr "~a: \"~a\" (prepared) on ~s\n" (sqlite3-database-name db) (sqlite3-statement-name stmt) args))
  (let ((p (sqlite3-statement-raw-pointer stmt)))
    (if (pair? args)
	(let ((exn (begin
		     (reset! stmt '())
		     (sqlite3-bind! db p args))))
	  (if exn (begin (reset! stmt args) (raise exn)))))
    (let ((r '())
	  (tm0 #f) (tm1 #f))
      (if (sqlite3-debug-statements) (set! tm0 (current-milliseconds)))
      (sqlite3-for-each
       db p
       (lambda (row)
	 (set! r (cons row r))))
      (if tm0 (set! tm1 (current-milliseconds)))
      (let ((r0 (list->vector
		 (cons
		  (sqlite3-columns p)
		  (reverse! r)))))
	(if (and tm0 tm1)
	    (let ((d (fp- tm1 tm0))
		  (n (sub1 (vector-length r0))))
	      (logerr "~a: ~a results in ~a ms (~a)\n"
		      (sqlite3-database-name db) n d
		      (and (> n 0) (fp/ d (exact->inexact n))))))
	;; See also "bind!": It is IMPORTANT that we keep a reference
	;; to the args list here.
	;;
	;; BEWARE: if the compiler was to only preserve the boolean
	;; value for (pair? args) we would loose badly…
	(if (pair? args) (reset! stmt args))
	r0))))

(define (sqlite3-exec*2 db stmt args)
  (if (sqlite3-database-raw-pointer db)
      (if (sqlite3-statement? stmt)
	  (if (sqlite3-statement-valid? db stmt)
	      (sqlite3-exec/prepared db stmt args)
	      (begin
		(set! stmt (sqlite3-prepare/while-locked db (sqlite3-statement-name stmt)))
		(sqlite3-exec/prepared db stmt args)))
	  (sqlite3-exec** db stmt args))
      (sqlite3-raise-closed db)))

(define (sqlite3-exec* db stmt . args)
  (if (sqlite3-database-raw-pointer db)
      (if (sqlite3-statement? stmt)
	  (if (sqlite3-statement-valid? db stmt)
	      (sqlite3-exec/prepared db stmt args)
	      (begin
		(set! stmt (sqlite3-prepare/while-locked db (sqlite3-statement-name stmt)))
		(sqlite3-exec/prepared db stmt args)))
	  (sqlite3-exec** db stmt args))
      (sqlite3-raise-closed db)))

;; This addition thread may or may be not required.  TODO: split into
;; two versions.

(: sqlite3-exec ((struct <sqlite3-database>) (or string (struct <sqlite3-statement>)) #!rest -> :sql-result:))
(define (sqlite3-exec db stmt . args)
  (define (cleanup! db)
   (and-let* ((p (sqlite3-database-open-statements db)))
             (set-sqlite3-database-open-statement! db #f)
	     (sqlite3-finalize db p)))
  (guard
   (ex #;((uncaught-exception? ex) (cleanup! db) (raise (uncaught-exception-reason ex)))
       (else (cleanup! db) (mutex-unlock! (sqlite3-database-mutex db)) (raise ex)))
   #;(let ((thunk (lambda ()
		  (with-mutex (sqlite3-database-mutex db)
			      (sqlite3-exec*2 db stmt args)))))
     (thread-join! (thread-start! (make-thread thunk "sqlite3-exec"))))
   #;(with-mutex (sqlite3-database-mutex db) (sqlite3-exec*2 db stmt args))
   (let ((result (begin (mutex-lock! (sqlite3-database-mutex db)) (sqlite3-exec*2 db stmt args))))
     (mutex-unlock! (sqlite3-database-mutex db))
     result)
   ))

#;(define (sqlite3-exec db stmt . args)
  (with-mutex (sqlite3-database-mutex db)
	      (sqlite3-exec*2 db stmt args)))

(: sqlite3-call-with-transaction
   ((struct <sqlite3-database>)
    (procedure ((procedure (string #!rest) :sql-result:)) :sql-result:)
    -> :sql-result:))
(define (sqlite3-call-with-transaction db proc)
  (guard
   (ex (else
	(guard
	 (ex (else #f))			; don't complain if no transaction active
	 (sqlite3-exec/prepared db (sqlite3-prepare/while-locked db "ROLLBACK") '()))
	(mutex-unlock! (sqlite3-database-mutex db))
	(raise ex)))
   (mutex-lock! (sqlite3-database-mutex db))
   (sqlite3-exec/prepared db (sqlite3-prepare/while-locked db "BEGIN IMMEDIATE TRANSACTION") '())
   (let ((r (proc (lambda (stmt . args)
		    (if (pair? args)
			(let ((prep (sqlite3-prepare/while-locked db stmt)))
			  (sqlite3-exec/prepared db prep args))
			(sqlite3-exec*2 db stmt args))))))
     (sqlite3-exec/prepared db (sqlite3-prepare/while-locked db "COMMIT") '())
     (mutex-unlock! (sqlite3-database-mutex db))
     r)))

(: sqlite3-call-test/set
   ((struct <sqlite3-database>)
    (procedure ((procedure (string) boolean)) boolean) ; test
    (procedure ((procedure (string) . *)) boolean)     ; set
    procedure ;;(procedure * . *)				       ; fail
    list					       ; fail-args
    -> boolean))
(define (sqlite3-call-test/set db test set fail fail-args)
  (or (guard
       (ex (else
	    (guard
	     (ex (else #f))			; don't complain if no transaction active
	     (sqlite3-exec* db "ROLLBACK"))
	    (mutex-unlock! (sqlite3-database-mutex db))
	    (raise ex)))
       (let ((sql (lambda (stmt . args)
		    (if (pair? args)
			(let ((prep (sqlite3-prepare/while-locked db stmt)))
			  (sqlite3-exec/prepared db prep args))
			(sqlite3-exec*2 db stmt args)))))
	 (mutex-lock! (sqlite3-database-mutex db))
	 (sqlite3-exec/prepared db (sqlite3-prepare/while-locked db "BEGIN IMMEDIATE TRANSACTION") '())
	 (if (test sql)
	     (begin
	       (set sql)
	       (sqlite3-exec/prepared db (sqlite3-prepare/while-locked db "COMMIT") '())
	       (mutex-unlock! (sqlite3-database-mutex db))
	       #t)
	     (begin
	       (sqlite3-exec/prepared db (sqlite3-prepare/while-locked db "ROLLBACK") '())
	       (mutex-unlock! (sqlite3-database-mutex db))
	       #f))))
      (apply fail fail-args)))

(define-foreign-variable CB_IO_TYPE_BLKSZ int "CB_IO_TYPE_BLKSZ")
(define-foreign-variable CB_IO_TYPE_FSIZE int "CB_IO_TYPE_FSIZE")
(define-foreign-variable CB_IO_TYPE_READ int "CB_IO_TYPE_READ")
(define-foreign-variable CB_IO_TYPE_WRITE int "CB_IO_TYPE_WRITE")
(define-foreign-variable CB_IO_TYPE_TRUNC int "CB_IO_TYPE_TRUNC")
(define-foreign-variable CB_IO_TYPE_CLOSE int "CB_IO_TYPE_CLOSE")

(define cba-buf
  (foreign-lambda* c-pointer ((<sqlite3-callback-args> arg)) "C_return(arg->buf);"))
(define cba-op
  (foreign-lambda* integer ((<sqlite3-callback-args> arg)) "C_return(arg->op & CB_OP_RETURN ? -1 : arg->op >> CB_OP_SHIFT);"))
(define set-cba-op!
  (foreign-lambda* void ((<sqlite3-callback-args> arg) (integer op)) "arg->op = op << CB_OP_SHIFT | CB_OP_RETURN;"))
(define cba-size
  (foreign-lambda* integer ((<sqlite3-callback-args> arg)) "C_return(arg->size);"))
(define cba-amount
  (foreign-lambda* integer ((<sqlite3-callback-args> arg)) "C_return(arg->amount);"))
(define cba-offset
  (foreign-lambda* integer ((<sqlite3-callback-args> arg)) "C_return(arg->offset);"))

(define set-cba-offset!
  (foreign-lambda* void ((<sqlite3-callback-args> arg) (integer off)) "arg->offset = off;"))

(define-type :sqlite3-return: symbol)
(define-type :sqlite3-vfs:
  (forall
   (a)
   (vector
    a
    (procedure (a) fixnum)			   ;; block-size
    (procedure (a) fixnum)			   ;; total-size
    (procedure (a pointer fixnum fixnum) :sqlite3-return:)   ;; read
    (procedure (a pointer fixnum fixnum) :sqlite3-return:)   ;; write
    (procedure (a fixnum) fixnum)		   ;; truncate!
    (procedure (a) *)				   ;; close
    )))
(: make-vfs
   (forall
    (a)
    (procedure
     (a
      (procedure (a) fixnum)			   ;; block-size
      (procedure (a) fixnum)			   ;; total-size
      (procedure (a pointer fixnum fixnum) :sqlite3-return:) ;; read
      (procedure (a pointer fixnum fixnum) :sqlite3-return:) ;; write
      (procedure (a fixnum) fixnum)		   ;; truncate!
      (procedure (a) *)				   ;; close
      )
     :sqlite3-vfs:)))
(define (make-vfs self block-size total-size read write truncate! close)
  (vector
   self
   block-size total-size
   read
   write
   truncate!
   close))

(define (callback-wrapper arg)
  (guard
   (ex (else (logerr "callback-wrapper failed ~s\n" ex #;(condition->string ex))
	     (set-cba-op! arg SQLITE_IOERR)))
   (let ((op ((foreign-lambda* integer ((<sqlite3-callback-args> arg))
			       "pthread_mutex_lock(&arg->mux);"
			       "while(!(arg->op & CB_OP_CALL)) pthread_cond_wait(&arg->cond, &arg->mux);"
			       "C_return(arg->op >> CB_OP_SHIFT);")
	      arg))
	 (ref ((foreign-lambda* scheme-object ((<sqlite3-callback-args> arg)) "C_return(CHICKEN_gc_root_ref(arg->ref));") arg)))
     (define opaque (vector-ref ref 0))
     (cond
      ((eq? op CB_IO_TYPE_READ)
       (let ((r ((vector-ref ref 3)
		 opaque (cba-buf arg) (cba-amount arg) (cba-offset arg))))
	 (set-cba-op! arg
		      (case r
			((SQLITE_OK) SQLITE_OK)
			((SQLITE_IOERR_SHORT_READ) SQLITE_IOERR_SHORT_READ)
			(else SQLITE_IOERR)))))
      ((eq? op CB_IO_TYPE_WRITE)
       (let ((r ((vector-ref ref 4)
		 opaque (cba-buf arg) (cba-amount arg) (cba-offset arg))))
	 (set-cba-op! arg SQLITE_OK)))
      ((eq? op CB_IO_TYPE_TRUNC)
       (let ((r ((vector-ref ref 5) opaque (cba-offset arg))))
	 (set-cba-op! arg SQLITE_OK)))
      ((eq? op CB_IO_TYPE_CLOSE)
       (set-cba-op! arg (if ((vector-ref ref 6) opaque) SQLITE_OK SQLITE_ERROR)))
      ((eq? op CB_IO_TYPE_FSIZE)
       (let ((s ((vector-ref ref 2) opaque)))
	 (set-cba-op! arg SQLITE_OK)
	 (set-cba-offset! arg s)))
      ((eq? op CB_IO_TYPE_BLKSZ)
       (let ((s ((vector-ref ref 1) opaque)))
	 (set-cba-op! arg SQLITE_OK)
	 (set-cba-offset! arg s)))
      (else (set-cba-op! arg SQLITE_IOERR)
	    (logerr "callback-wrapper unknown request ~a\n" op)))))
  ((foreign-lambda*
    integer ((<sqlite3-callback-args> arg))
    "pthread_mutex_unlock(&arg->mux);"
    "C_return(pthread_cond_signal(&arg->cond));")
   arg))

((foreign-lambda void "callback_sqlite3_vfs_init" nonnull-c-pointer nonnull-c-pointer)
 (make-gc-root callback-wrapper)
 (make-gc-root
  (foreign-lambda* <sqlite3-callback-args> (((nonnull-c-pointer <sqlite3-callback-args>) arg)) "C_return(*arg);")))

)
