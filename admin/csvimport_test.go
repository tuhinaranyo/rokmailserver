package main

import (
	"strings"
	"testing"
)

const goodCSV = `email,name,type,department,quota_mb,forward_to,members,role
Alice@Example.com,Alice,mailbox,Sales,2048,,,user
bob@example.com,Bob,mailbox,Sales,,"x@ext.org, y@ext.org",,helpdesk
sales@example.com,Sales team,alias,Sales,,,alice@example.com:send;bob@example.com;ext@other.org,
`

func TestImportValid(t *testing.T) {
	e := newEnv(t)
	res, err := importCSV(e.db, strings.NewReader(goodCSV), "cli", "", 1024)
	if err != nil || len(res.Errors) > 0 {
		t.Fatalf("import: %v %v", err, res)
	}
	if res.Created != 3 || len(res.Creds) != 2 {
		t.Fatalf("created=%d creds=%d", res.Created, len(res.Creds))
	}
	a, err := loadAccountByEmail(e.db, "alice@example.com")
	if err != nil || a.Quota != 2048 || a.DeptName != "Sales" || a.Role != RoleUser {
		t.Fatalf("alice: %+v %v", a, err)
	}
	b, _ := loadAccountByEmail(e.db, "bob@example.com")
	if b.Forward != "x@ext.org,y@ext.org" || b.Role != RoleHelpdesk || b.Quota != 1024 {
		t.Errorf("bob: %+v", b)
	}
	var h string
	e.db.QueryRow(`SELECT password FROM accounts WHERE email='alice@example.com'`).Scan(&h)
	pw := ""
	for _, c := range res.Creds {
		if c[0] == "alice@example.com" {
			pw = c[1]
		}
	}
	if !verifyPassword(h, pw) {
		t.Error("credential password does not match stored hash")
	}
	if n := e.count(`SELECT COUNT(*) FROM alias_members WHERE can_send=1`); n != 1 {
		t.Errorf("send-as members: %d", n)
	}
	// idempotent re-run: updates, no new credentials
	res, err = importCSV(e.db, strings.NewReader(goodCSV), "cli", "", 1024)
	if err != nil || len(res.Errors) > 0 || res.Created != 0 || res.Updated != 3 || len(res.Creds) != 0 {
		t.Fatalf("rerun: %v %+v", err, res)
	}
	if n := e.count(`SELECT COUNT(*) FROM departments`); n != 1 {
		t.Errorf("departments: %d", n)
	}
	if n := e.count(`SELECT COUNT(*) FROM audit_log WHERE action='csv.import'`); n != 2 {
		t.Errorf("audit entries: %d", n)
	}
}

func TestImportInvalidWritesNothing(t *testing.T) {
	e := newEnv(t)
	e.addAccount("taken@example.com", RoleUser, 0)
	before := e.count(`SELECT COUNT(*) FROM accounts`)
	bad := `email,name,type,department,quota_mb,forward_to,members,role
ok@example.com,Ok,mailbox,NewDept,,,,user
bad@nodomain.invalid,Bad,mailbox,,,,,user
taken@example.com,Dup,alias,,,,a@example.com,
ok@example.com,Again,mailbox,,,,,user
x@example.com,X,mailbox,,abc,,,user
y@example.com,Y,mailbox,,,,,wizard
z@example.com,Z,whatever,,,,,
`
	res, err := importCSV(e.db, strings.NewReader(bad), "cli", "", 1024)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Errors) != 6 {
		t.Fatalf("want 6 errors, got %d: %v", len(res.Errors), res.Errors)
	}
	if !strings.HasPrefix(res.Errors[0], "line 3:") {
		t.Errorf("line numbers: %v", res.Errors)
	}
	if got := e.count(`SELECT COUNT(*) FROM accounts`); got != before {
		t.Errorf("accounts written: %d -> %d", before, got)
	}
	if e.count(`SELECT COUNT(*) FROM departments`) != 0 || e.count(`SELECT COUNT(*) FROM aliases`) != 0 {
		t.Error("departments/aliases written despite errors")
	}
	if e.count(`SELECT COUNT(*) FROM audit_log WHERE action LIKE 'csv%' OR action LIKE 'account.create'`) != 0 {
		t.Error("audit written despite rollback")
	}
}

func TestImportBadHeader(t *testing.T) {
	e := newEnv(t)
	if _, err := importCSV(e.db, strings.NewReader("email,name\na@example.com,A\n"), "cli", "", 1024); err == nil {
		t.Error("missing columns must be rejected")
	}
}

func TestImportCannotDemoteLastSuperadmin(t *testing.T) {
	e := newEnv(t)
	e.addAccount("root@example.com", RoleSuper, 0)
	res, _ := importCSV(e.db, strings.NewReader("email,name,type,department,quota_mb,forward_to,members,role\nroot@example.com,,mailbox,,,,,user\n"), "cli", "", 1024)
	if len(res.Errors) != 1 {
		t.Fatalf("expected guard error: %+v", res)
	}
}
