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


# Author

Jörg F. Wittenberger

# License

BSD
