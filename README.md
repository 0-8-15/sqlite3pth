# sqlite3pth
Run SQLite queries asynchronously in pthreads.  Supports calling Scheme from SQLite's VFS to supply database block storage.

Offloads the SQL work to pthreads; the chicken thread is free to continue.

VFS support allows sqlite3 to call back into chicken to supply blocks
of the data base.  (This is a breakout from ball.askemos.org - where
the VFS is used to implement versioning and replication of the
databases.)

# Issues

* So far not tested with the official srfi-34 from chicken repos.  In
  case of problems please try
  [mine](http://askemos.org/chicken-eggs/index.html).

* Automatic installation fails.  Try something like:

        $ chicken-install -r sqlite3pth
        $ cd sqlite3pth
        # set BUILT_SQLITE3=/path/to/sqlite3 build directory from successful sqlite3 build
        $ ln -s $BUILT_SQLITE3 sqlite # BUILT_SQLITE3
        $ chicken-install

   (Sorry for this.  For this.  I can not rely on system installed
   sqlite but must be sure to have the exact version.  Otherwise the
   hashes of the resulting database content will not match and
   replication break. Patches for this are very welcome.)

* API is not perfect.

# Requirements

pthreads, srfi-34

# API

TBD.

    sql-null sql-null? sql-not  ;; should be imported from sql-null instead
    ;;
    (:sql-result: string --> (or false fixnum)) convert field name to index
    ;;
    (: sqlite3-prepare ((struct <sqlite3-database>) string --> (struct <sqlite3-statement>)))
    (: sqlite3-exec ((struct <sqlite3-database>) (or string (struct <sqlite3-statement>)) #!rest -> :sql-result:))
    (: sqlite3-call-with-transaction
       ((struct <sqlite3-database>)
        (procedure ((procedure (string #!rest) :sql-result:)) :sql-result:)
       -> :sql-result:))
    sqlite3-call-test/set ;; questionable
    (: sqlite3-close ((struct <sqlite3-database>) -> . *))
    sqlite3-interrupt!
    sql-result? ;; test result type
    sql-value ;; (sql-value RESULT ROW FIELD) --> *

    (: sql-ref (:sql-result: (or boolean fixnum) (or boolean fixnum string symbol) --> *))
    (: sql-fold (:sql-result: (procedure ((procedure (fixnum) *) *) *) * -> *))

    (: sqlite3-open-restricted (string #!optional string vector --> (struct <sqlite3-database>)))
    Restricted open optionally with VFS.  SQL may not attach other files.
    optional string requests sqlite3 VFS, vector holds VFS callbacks

    (: sqlite3-open-restricted-ro (string #!optional string vector --> (struct <sqlite3-database>)))
    Restricted open read only optionally with VFS.  SQL may not attach other files.
    optional string requests sqlite3 VFS, vector holds VFS callbacks

    sqlite3-database-name
    sqlite3-changes
    sqlite3-statement?
    sqlite3-statement-name
    sqlite3-error? sqlite3-error-code sqlite3-error-args
    sqlite3-error-db-locked?
    sqlite3-open sqlite3-close

    ;; debug aid
    sqlite3-debug-statements

# Examples

    (define db (sqlite-open "path"))
    (sqlite3-exec db "select 1") ; 1
    (sqlite3-exec db (sqlite3-prepare andavari-db "select ?1") 1) ; 1

    ;; Simplyfied example from ball.askemos.org.
    (define (sqlite3-open-ro/f_b frame block-table)
     (sqlite3-open-restricted-ro
      (literal (aggregate-entity frame)) ;; a string, data base name for sqlite3
      "askemos"
      (make-block-handler block-table)))

# VFS API

Current limitation: only calls to the main database are forwared.
Journal files are not yet supported at all.  I'd like this to be
changed.  Originally it was by intention.  We only needed the SQL
interpreter in our context.  Transaction are maintained at the network
level anyway.  Hence I still don't have much need.

`make-vfs SELF BLOCKSIZE TOTALSIZE READ WRITE TRUNCATE! CLOSE` --> VFSFILE

    (: make-vfs
       (forall
        (a)
        (procedure
         (a
          (procedure (a) fixnum)		       ;; block-size
          (procedure (a) fixnum)		       ;; total-size
          (procedure (a pointer fixnum fixnum) symbol) ;; read
          (procedure (a pointer fixnum fixnum) symbol) ;; write
          (procedure (a fixnum) fixnum)		       ;; truncate!
          (procedure (a) *)                            ;; close
          )
         :sqlite3-vfs:)))

Creates a VFSFILE object suitable as third argument (second optional arg) to
`sqlite3-open-restricted` and `sqlite3-open-restricted-ro`.

`SELF`: opaque handle being passed as initial argument to vfs-methods.

`BLOCKSIZE`: Returns block size for `VFSFILE`.

`TOTALSIZE`: Returns size of the sqlite3 database.

`READ`: Procedure of four arguments: VFSFILE, target pointer, number of
bytes to supply, offset in virtual file.

`WRITE`: Procedure of 4 arguments: VFSFILE, source pointer, number of
bytes to write to backing store, offset in virtual file.

`TRUNCATE!`: Truncates VFSFILE file given as first argument at
position given as second argument.

`CLOSE`: Closes VFSFILE.

# VFS Examples

    #;1> (use llrb-tree sqlite3pth lolevel)

    ; loading ...
    ; loading ...
    ; ...
    ; loading library lolevel ...
    #;2> ;; Backing-store is a string of 8x4096 bytes only.
    (define-values (vfsfile backing-store)
      (let* ((bsz 4096)
	     (fszmx (* bsz 8))
	     (store (make-string fszmx #\x0))
	     (fsz 0))
	(values
	 (make-vfs
	  store
	  (lambda (_) bsz)
	  (lambda (_) fsz)
	  (lambda (_ to n off) ;; read
	    (move-memory! store to n off 0)
	    (if (< fsz (+ n off)) 'SQLITE_IOERR_SHORT_READ 'SQLITE_OK))
	  (lambda (_ from n off) ;; write
	    (set! fsz (max fsz (+ n off)))
	    (move-memory! from store n 0 off)
	    'SQLITE_OK)
	  (lambda (n) (set! fsz (min fsz n)) 'SQLITE_OK)
	  (lambda (_) #t))
	 store)))
    #;3> (define db
      (sqlite3-open-restricted
       "/tmp/db"
       "askemos"
       vfsfile))
    #;4> (sqlite3-exec db "create table pairs (a integer, d integer)")
    #;5> (define (xkns a b) (sqlite3-exec db "insert into pairs values(?1, ?2)" a b))
    #;6> (xkns 1 2)
    #(#())
    #;7> (xkns 1 3)
    #(#())
    #;8> (xkns 3 4)
    #(#())
    #;9> (sql-fold
     (sqlite3-exec db "select * from pairs")
     (lambda (column initial) `((,(column 0) . ,(column 1)) . ,initial))
     '())
    ((3 . 4) (1 . 3) (1 . 2))
    #;10> (sql-ref
     (sqlite3-exec db "select * from pairs where a = ?1" 3)
     0 "d")
    4
    #;11> ;; Close and reopen...
    (sqlite3-close db)
    #;12> (set! db
	  (sqlite3-open-restricted
	   "/tmp/db"
	   "askemos"
	   vfsfile))
    #;13> (sql-ref
     (sqlite3-exec db "select * from pairs where a = ?1" 3)
     0 1)
    4
    #;14> (sql-fold
     (sqlite3-exec db "select * from pairs")
     (lambda (column initial) `((,(column 0) . ,(column 1)) . ,initial))
     '())

    ((3 . 4) (1 . 3) (1 . 2))
    #;15> 


# Author

Jörg F. Wittenberger

# License

BSD
