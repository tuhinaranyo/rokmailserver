package main

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func col(t *testing.T, e *testEnv, q string, args ...any) []string {
	t.Helper()
	rows, err := e.db.Query(q, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var s string
		rows.Scan(&s)
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func TestViewForward(t *testing.T) {
	e := newEnv(t)
	e.addAccount("a@example.com", RoleUser, 0)
	e.addAccount("b@example.com", RoleUser, 0)
	e.addAccount("c@example.com", RoleUser, 0)
	fwd := func(addr string) []string {
		return col(t, e, `SELECT destination FROM v_forward WHERE address=?`, addr)
	}
	if got := fwd("a@example.com"); len(got) != 0 {
		t.Errorf("no forwarding: %v", got)
	}
	e.db.Exec(`UPDATE accounts SET forward_to='x@ext.org,y@ext.org',keep_copy=1 WHERE email='a@example.com'`)
	if got, want := fwd("a@example.com"), []string{"a@example.com", "x@ext.org,y@ext.org"}; !reflect.DeepEqual(got, want) {
		t.Errorf("forward with copy: %v", got)
	}
	e.db.Exec(`UPDATE accounts SET keep_copy=0 WHERE email='a@example.com'`)
	if got, want := fwd("a@example.com"), []string{"x@ext.org,y@ext.org"}; !reflect.DeepEqual(got, want) {
		t.Errorf("forward without copy: %v", got)
	}
	e.db.Exec(`UPDATE accounts SET active=0 WHERE email='a@example.com'`)
	if got := fwd("a@example.com"); len(got) != 0 {
		t.Errorf("inactive account must not forward: %v", got)
	}

	e.db.Exec(`INSERT INTO aliases(id,address) VALUES(1,'team@example.com')`)
	e.db.Exec(`INSERT INTO alias_members VALUES(1,'b@example.com',1),(1,'c@example.com',0),(1,'ext@other.org',0)`)
	if got, want := fwd("team@example.com"), []string{"b@example.com", "c@example.com", "ext@other.org"}; !reflect.DeepEqual(got, want) {
		t.Errorf("alias fan-out: %v", got)
	}
	e.db.Exec(`UPDATE aliases SET active=0 WHERE id=1`)
	if got := fwd("team@example.com"); len(got) != 0 {
		t.Errorf("inactive alias must not resolve: %v", got)
	}
}

func TestViewSender(t *testing.T) {
	e := newEnv(t)
	e.addAccount("b@example.com", RoleUser, 0)
	e.addAccount("c@example.com", RoleUser, 0)
	snd := func(addr string) []string {
		return col(t, e, `SELECT login FROM v_sender WHERE address=?`, addr)
	}
	if got := snd("b@example.com"); !reflect.DeepEqual(got, []string{"b@example.com"}) {
		t.Errorf("own address: %v", got)
	}
	e.db.Exec(`INSERT INTO aliases(id,address) VALUES(1,'team@example.com')`)
	e.db.Exec(`INSERT INTO alias_members VALUES(1,'b@example.com',1),(1,'c@example.com',0),(1,'ext@other.org',1)`)
	if got := snd("team@example.com"); !reflect.DeepEqual(got, []string{"b@example.com"}) {
		t.Errorf("only send-as local member: %v", got)
	}
	e.db.Exec(`UPDATE accounts SET can_send=0 WHERE email='b@example.com'`)
	if got := snd("team@example.com"); len(got) != 0 {
		t.Errorf("receive-only member: %v", got)
	}
	if got := snd("b@example.com"); len(got) != 0 {
		t.Errorf("receive-only own address: %v", got)
	}
	e.db.Exec(`UPDATE accounts SET can_send=1 WHERE email='b@example.com'`)
	e.db.Exec(`UPDATE accounts SET active=0 WHERE email='b@example.com'`)
	if got := snd("team@example.com"); len(got) != 0 {
		t.Errorf("inactive member: %v", got)
	}
	e.db.Exec(`UPDATE accounts SET active=1 WHERE email='b@example.com'`)
	e.db.Exec(`UPDATE aliases SET active=0 WHERE id=1`)
	if got := snd("team@example.com"); len(got) != 0 {
		t.Errorf("inactive alias: %v", got)
	}
}

func TestDBFilesWorldReadable(t *testing.T) {
	e := newEnv(t)
	e.addAccount("a@example.com", RoleUser, 0)
	p := e.app.cfg.DBPath
	for _, f := range []string{p, p + "-wal", p + "-shm"} {
		st, err := os.Stat(f)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if st.Mode().Perm() != 0o666 {
			t.Errorf("%s mode %v, want 0666", filepath.Base(f), st.Mode().Perm())
		}
	}
	if st, _ := os.Stat(filepath.Dir(p)); st.Mode().Perm() != 0o777 {
		t.Errorf("dir mode %v, want 0777", st.Mode().Perm())
	}
	var fk, bt int
	e.db.QueryRow(`PRAGMA foreign_keys`).Scan(&fk)
	e.db.QueryRow(`PRAGMA busy_timeout`).Scan(&bt)
	if fk != 1 || bt == 0 {
		t.Errorf("pragmas fk=%d busy_timeout=%d", fk, bt)
	}
}

func TestPasswordFormatAndValidation(t *testing.T) {
	h, err := hashPassword("abcdefghij")
	if err != nil || !strings.HasPrefix(h, "{BLF-CRYPT}$2a$10$") {
		t.Fatalf("hash %q %v", h, err)
	}
	if !verifyPassword(h, "abcdefghij") || verifyPassword(h, "wrong") {
		t.Error("verify")
	}
	if checkPassword("short") == nil || checkPassword("exactly-ten") != nil {
		t.Error("min length")
	}
	for _, bad := range []string{"a", "a@b", "@example.com", "a b@example.com", "a@@example.com", "a@example", "a..b@example.com", "a/b@example.com"} {
		if _, err := normAddr(bad); err == nil {
			t.Errorf("%q should be invalid", bad)
		}
	}
	if a, err := normAddr(" John.Doe+x@Example.COM "); err != nil || a != "john.doe+x@example.com" {
		t.Errorf("normalize: %q %v", a, err)
	}
	if f, err := normForward("A@x.org, b@y.org;a@x.org", "me@example.com"); err != nil || f != "a@x.org,b@y.org" {
		t.Errorf("forward: %q %v", f, err)
	}
}

func TestDKIMKey(t *testing.T) {
	dir := t.TempDir()
	if err := ensureDKIM(dir, "example.com"); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(dir, "example.com.mail.key"))
	if err != nil || st.Mode().Perm() != 0o644 {
		t.Fatalf("key file: %v %v", st, err)
	}
	if p, err := dkimPublic(dir, "example.com"); err != nil || len(p) < 300 {
		t.Errorf("public key: %q %v", p, err)
	}
}
