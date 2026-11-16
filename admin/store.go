package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

type querier interface {
	QueryRow(string, ...any) *sql.Row
	Query(string, ...any) (*sql.Rows, error)
	Exec(string, ...any) (sql.Result, error)
}

// openDB creates the DB so another container/user can read it in WAL mode.
func openDB(path string) (*sql.DB, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o777); err != nil {
		return nil, err
	}
	_ = os.Chmod(dir, 0o777)
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)" +
		"&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	if _, err := db.Exec(schemaSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	for _, s := range []string{"", "-wal", "-shm"} {
		_ = os.Chmod(path+s, 0o666)
	}
	return db, nil
}

func tx(db *sql.DB, f func(*sql.Tx) error) error {
	t, err := db.Begin()
	if err != nil {
		return err
	}
	if err := f(t); err != nil {
		t.Rollback()
		return err
	}
	return t.Commit()
}

func audit(q querier, actor, action, target, detail, ip string) {
	q.Exec(`INSERT INTO audit_log(actor,action,target,detail,ip) VALUES(?,?,?,?,?)`, actor, action, target, detail, ip)
}

func exists(q querier, query string, args ...any) bool {
	var one int
	return q.QueryRow(query, args...).Scan(&one) == nil
}

// ---- accounts ----

type Account struct {
	ID       int64
	Email    string
	Name     string
	Role     string
	Dept     int64
	DeptName string
	Quota    int
	CanSend  bool
	Forward  string
	KeepCopy bool
	Active   bool
	Created  string
}

func (a Account) Target() Target { return Target{a.Role, a.Dept} }

const accountCols = `a.id,a.email,a.name,a.role,COALESCE(a.department_id,0),COALESCE(d.name,''),a.quota_mb,a.can_send,a.forward_to,a.keep_copy,a.active,a.created_at`
const accountFrom = ` FROM accounts a LEFT JOIN departments d ON d.id=a.department_id `

type scanner interface{ Scan(...any) error }

func scanAccount(s scanner) (Account, error) {
	var a Account
	err := s.Scan(&a.ID, &a.Email, &a.Name, &a.Role, &a.Dept, &a.DeptName, &a.Quota, &a.CanSend, &a.Forward, &a.KeepCopy, &a.Active, &a.Created)
	return a, err
}

func loadAccount(q querier, id int64) (Account, error) {
	a, err := scanAccount(q.QueryRow(`SELECT `+accountCols+accountFrom+`WHERE a.id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return a, errNotFound
	}
	return a, err
}

func loadAccountByEmail(q querier, email string) (Account, error) {
	a, err := scanAccount(q.QueryRow(`SELECT `+accountCols+accountFrom+`WHERE a.email=?`, email))
	if errors.Is(err, sql.ErrNoRows) {
		return a, errNotFound
	}
	return a, err
}

// AccIn is the editable part of an account.
type AccIn struct {
	Email    string
	Name     string
	Role     string
	Dept     int64
	Quota    int
	CanSend  bool
	Forward  string
	KeepCopy bool
}

func deptOrNil(d int64) any {
	if d == 0 {
		return nil
	}
	return d
}

// normalize validates and lowercases the input. create=true also checks the
// email (domain exists, no clash with an alias or another account).
func (in *AccIn) normalize(q querier, create bool) error {
	if create {
		e, err := normAddr(in.Email)
		if err != nil {
			return err
		}
		in.Email = e
		if !exists(q, `SELECT 1 FROM domains WHERE name=?`, domainOf(e)) {
			return bad("domain %q does not exist", domainOf(e))
		}
		if exists(q, `SELECT 1 FROM aliases WHERE address=?`, e) {
			return bad("%s is already an alias", e)
		}
		if exists(q, `SELECT 1 FROM accounts WHERE email=?`, e) {
			return bad("%s already exists", e)
		}
	}
	in.Name = strings.TrimSpace(in.Name)
	if len(in.Name) > 100 {
		return bad("name too long")
	}
	if !validRole(in.Role) {
		return bad("invalid role %q", in.Role)
	}
	if in.Dept != 0 && !exists(q, `SELECT 1 FROM departments WHERE id=?`, in.Dept) {
		return bad("unknown department")
	}
	if in.Quota < 1 || in.Quota > 10_000_000 {
		return bad("quota must be between 1 and 10000000 MB")
	}
	f, err := normForward(in.Forward, in.Email)
	if err != nil {
		return err
	}
	in.Forward = f
	return nil
}

func insertAccount(q querier, in AccIn, pwHash string) (int64, error) {
	r, err := q.Exec(`INSERT INTO accounts(email,name,password,role,department_id,quota_mb,can_send,forward_to,keep_copy)
		VALUES(?,?,?,?,?,?,?,?,?)`, in.Email, in.Name, pwHash, in.Role, deptOrNil(in.Dept), in.Quota, in.CanSend, in.Forward, in.KeepCopy)
	if err != nil {
		return 0, err
	}
	return r.LastInsertId()
}

func updateAccount(q querier, id int64, in AccIn) error {
	_, err := q.Exec(`UPDATE accounts SET name=?,role=?,department_id=?,quota_mb=?,can_send=?,forward_to=?,keep_copy=?,updated_at=datetime('now') WHERE id=?`,
		in.Name, in.Role, deptOrNil(in.Dept), in.Quota, in.CanSend, in.Forward, in.KeepCopy, id)
	return err
}

func killSessions(q querier, accountID int64) {
	q.Exec(`DELETE FROM sessions WHERE account_id=?`, accountID)
}

func activeSuperadmins(q querier) int {
	var n int
	q.QueryRow(`SELECT COUNT(*) FROM accounts WHERE role='superadmin' AND active=1`).Scan(&n)
	return n
}

func guardLastSuper(q querier, t Account, newRole string, newActive, deleting bool) error {
	return GuardLastSuperadmin(t.Role, t.Active, activeSuperadmins(q), newRole, newActive, deleting)
}

// ---- departments ----

func deptByName(q querier, name string, create bool) (int64, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return 0, nil
	}
	var id int64
	err := q.QueryRow(`SELECT id FROM departments WHERE name=?`, name).Scan(&id)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	if !create {
		return 0, bad("unknown department %q", name)
	}
	if len(name) > 60 {
		return 0, bad("department name too long")
	}
	r, err := q.Exec(`INSERT INTO departments(name) VALUES(?)`, name)
	if err != nil {
		return 0, err
	}
	return r.LastInsertId()
}

type Dept struct {
	ID       int64
	Name     string
	Accounts int
	Aliases  int
}

func listDepts(q querier) ([]Dept, error) {
	rows, err := q.Query(`SELECT d.id,d.name,
		(SELECT COUNT(*) FROM accounts WHERE department_id=d.id),
		(SELECT COUNT(*) FROM aliases WHERE department_id=d.id) FROM departments d ORDER BY d.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Dept
	for rows.Next() {
		var d Dept
		if err := rows.Scan(&d.ID, &d.Name, &d.Accounts, &d.Aliases); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// ---- aliases ----

type Member struct {
	Dest string
	Send bool
}

type Alias struct {
	ID       int64
	Address  string
	Desc     string
	Dept     int64
	DeptName string
	Active   bool
	Created  string
	Members  []Member
}

const aliasCols = `a.id,a.address,a.description,COALESCE(a.department_id,0),COALESCE(d.name,''),a.active,a.created_at`
const aliasFrom = ` FROM aliases a LEFT JOIN departments d ON d.id=a.department_id `

func scanAlias(s scanner) (Alias, error) {
	var a Alias
	err := s.Scan(&a.ID, &a.Address, &a.Desc, &a.Dept, &a.DeptName, &a.Active, &a.Created)
	return a, err
}

func loadAlias(q querier, id int64) (Alias, error) {
	a, err := scanAlias(q.QueryRow(`SELECT `+aliasCols+aliasFrom+`WHERE a.id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return a, errNotFound
	}
	if err != nil {
		return a, err
	}
	rows, err := q.Query(`SELECT destination,can_send FROM alias_members WHERE alias_id=? ORDER BY destination`, id)
	if err != nil {
		return a, err
	}
	defer rows.Close()
	for rows.Next() {
		var m Member
		if err := rows.Scan(&m.Dest, &m.Send); err != nil {
			return a, err
		}
		a.Members = append(a.Members, m)
	}
	return a, rows.Err()
}

func loadAliasByAddress(q querier, addr string) (int64, error) {
	var id int64
	err := q.QueryRow(`SELECT id FROM aliases WHERE address=?`, addr).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, errNotFound
	}
	return id, err
}

func membersText(ms []Member) string {
	var b strings.Builder
	for _, m := range ms {
		b.WriteString(m.Dest)
		if m.Send {
			b.WriteString(":send")
		}
		b.WriteString("\n")
	}
	return b.String()
}

// parseMembers parses "addr" / "addr:send" tokens.
func parseMembers(q querier, alias, s string) ([]Member, error) {
	var out []Member
	seen := map[string]bool{}
	for _, tok := range splitList(s) {
		send := false
		if strings.HasSuffix(strings.ToLower(tok), ":send") {
			send, tok = true, tok[:len(tok)-5]
		}
		d, err := normAddr(tok)
		if err != nil {
			return nil, err
		}
		if d == alias {
			return nil, bad("alias cannot be a member of itself")
		}
		if send && !exists(q, `SELECT 1 FROM domains WHERE name=?`, domainOf(d)) {
			return nil, bad("%s: send-as is only possible for local addresses", d)
		}
		if seen[d] {
			return nil, bad("duplicate member %s", d)
		}
		seen[d] = true
		out = append(out, Member{d, send})
	}
	if len(out) == 0 {
		return nil, bad("an alias needs at least one member")
	}
	return out, nil
}

func checkAliasAddress(q querier, addr string) (string, error) {
	a, err := normAddr(addr)
	if err != nil {
		return "", err
	}
	if !exists(q, `SELECT 1 FROM domains WHERE name=?`, domainOf(a)) {
		return "", bad("domain %q does not exist", domainOf(a))
	}
	if exists(q, `SELECT 1 FROM accounts WHERE email=?`, a) {
		return "", bad("%s is already an account", a)
	}
	return a, nil
}

func setMembers(q querier, aliasID int64, ms []Member) error {
	if _, err := q.Exec(`DELETE FROM alias_members WHERE alias_id=?`, aliasID); err != nil {
		return err
	}
	for _, m := range ms {
		if _, err := q.Exec(`INSERT INTO alias_members(alias_id,destination,can_send) VALUES(?,?,?)`, aliasID, m.Dest, m.Send); err != nil {
			return err
		}
	}
	return nil
}

// ---- bootstrap + DKIM ----

func ensureDomain(q querier, name string) error {
	_, err := q.Exec(`INSERT OR IGNORE INTO domains(name) VALUES(?)`, name)
	return err
}

func bootstrap(db *sql.DB, cfg Config) error {
	if cfg.PrimaryDomain != "" {
		d, err := normDomain(cfg.PrimaryDomain)
		if err != nil {
			return err
		}
		if err := ensureDomain(db, d); err != nil {
			return err
		}
	}
	if activeSuperadmins(db) > 0 || cfg.AdminEmail == "" || cfg.AdminPassword == "" {
		return nil
	}
	return tx(db, func(t *sql.Tx) error {
		email, err := normAddr(cfg.AdminEmail)
		if err != nil {
			return err
		}
		if err := checkPassword(cfg.AdminPassword); err != nil {
			return err
		}
		if err := ensureDomain(t, domainOf(email)); err != nil {
			return err
		}
		_, err = upsertSuperadmin(t, email, cfg.AdminPassword, cfg.DefaultQuota)
		if err == nil {
			audit(t, "cli", "account.bootstrap", email, "", "")
		}
		return err
	})
}

// upsertSuperadmin creates the account or promotes/reactivates it and sets the password.
func upsertSuperadmin(q querier, email, password string, quota int) (int64, error) {
	h, err := hashPassword(password)
	if err != nil {
		return 0, err
	}
	if a, err := loadAccountByEmail(q, email); err == nil {
		_, err = q.Exec(`UPDATE accounts SET role='superadmin',active=1,password=?,updated_at=datetime('now') WHERE id=?`, h, a.ID)
		return a.ID, err
	}
	in := AccIn{Email: email, Role: RoleSuper, Quota: quota, CanSend: true, KeepCopy: true}
	if err := in.normalize(q, true); err != nil {
		return 0, err
	}
	return insertAccount(q, in, h)
}

func dkimPath(dir, domain string) string { return filepath.Join(dir, domain+".mail.key") }

func ensureDKIM(dir, domain string) error {
	p := dkimPath(dir, domain)
	if _, err := os.Stat(p); err == nil {
		return nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	b := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

func ensureAllDKIM(db *sql.DB, dir string) error {
	rows, err := db.Query(`SELECT name FROM domains`)
	if err != nil {
		return err
	}
	var names []string
	for rows.Next() {
		var n string
		rows.Scan(&n)
		names = append(names, n)
	}
	rows.Close()
	for _, n := range names {
		if err := ensureDKIM(dir, n); err != nil {
			return fmt.Errorf("dkim %s: %w", n, err)
		}
	}
	return nil
}

// dkimPublic returns the base64 public key for the DNS record.
func dkimPublic(dir, domain string) (string, error) {
	b, err := os.ReadFile(dkimPath(dir, domain))
	if err != nil {
		return "", err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return "", errors.New("bad PEM")
	}
	k, err := x509.ParsePKCS1PrivateKey(blk.Bytes)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(der), nil
}
