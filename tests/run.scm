(use sqlite3pth lolevel)

;; Backing-store is a string of 8x4096 bytes only.
(define-values (vfsfile backing-store)
  (let* ((bsz 4096)
	 (fszmx (* bsz 8))
	 (store (cons 0 (make-string fszmx #\x0))))
    (define fsz car) (define fsz! set-car!) (define fbuf cdr)
    (values
     (make-vfs
      store
      (lambda (_) bsz)
      (lambda (store) (fsz store))
      (lambda (store to n off) ;; read
	(move-memory! (fbuf store) to n off 0)
	(if (< (fsz store) (+ n off)) 'SQLITE_IOERR_SHORT_READ 'SQLITE_OK))
      (lambda (store from n off) ;; write
	(fsz! store (max (fsz store) (+ n off)))
	(move-memory! from (fbuf store) n 0 off)
	'SQLITE_OK)
      (lambda (store n) (fsz! store (min (fsz store) n)) 'SQLITE_OK)
      (lambda (store) #t))
     store)))

(define db
  (sqlite3-open-restricted
   "/tmp/db"
   "askemos"
   vfsfile))

(sqlite3-exec db "create table pairs (a integer, d integer)")

(define (xkns a b) (sqlite3-exec db "insert into pairs values(?1, ?2)" a b))

(xkns 1 2)
(xkns 1 3)
(xkns 3 4)

(assert
 (equal?
  (sql-fold
   (sqlite3-exec db "select * from pairs")
   (lambda (column initial) `((,(column 0) . ,(column 1)) . ,initial))
   '())
  '((3 . 4) (1 . 3) (1 . 2))))

(assert
 (= (sql-ref
     (sqlite3-exec db "select * from pairs where a = ?1" 3)
     0 "d")
    4))

;; Close and reopen...
(sqlite3-close db)

(set! db
      (sqlite3-open-restricted
       "/tmp/db"
       "askemos"
       vfsfile))

(assert
 (= (sql-ref
     (sqlite3-exec db "select * from pairs where a = ?1" 3)
     0 1)
    4))

