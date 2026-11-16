package main

import (
	"net/url"
	"strconv"
	"strings"
	"testing"
)

func expect(t *testing.T, what string, got int, want ...int) {
	t.Helper()
	for _, w := range want {
		if got == w {
			return
		}
	}
	t.Errorf("%s: status %d, want one of %v", what, got, want)
}

func TestLoginAndHealthz(t *testing.T) {
	e := newEnv(t)
	e.addAccount("u@example.com", RoleUser, 0)
	c := e.newClient()
	code, body, _ := c.get("/healthz")
	if code != 200 || !strings.Contains(body, "ok") {
		t.Errorf("healthz %d", code)
	}
	if code, _, loc := c.get("/accounts"); code != 303 || loc != "/login" {
		t.Errorf("unauthenticated: %d %s", code, loc)
	}
	if code, _, _ := c.login("u@example.com", "wrong-password"); code != 401 {
		t.Errorf("wrong password: %d", code)
	}
	if code, _, _ := c.login("nobody@example.com", "whatever-pass"); code != 401 {
		t.Errorf("unknown user: %d", code)
	}
	if code, _, loc := c.login("u@example.com", testPW); code != 303 || loc != "/" {
		t.Errorf("login: %d %s", code, loc)
	}
	if code, body, _ := c.get("/"); code != 200 || !strings.Contains(body, "Dashboard") {
		t.Errorf("dashboard %d", code)
	}
	// session cookie flags + headers
	resp, err := c.c.Get(c.base + "/me")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if !strings.Contains(resp.Header.Get("Content-Security-Policy"), "default-src 'self'") || resp.Header.Get("X-Frame-Options") != "DENY" {
		t.Error("security headers missing")
	}
}

func TestLoginCSRFAndThrottle(t *testing.T) {
	e := newEnv(t)
	e.addAccount("u@example.com", RoleUser, 0)
	c := e.newClient()
	if code, _, _ := c.postRaw("/login", url.Values{"email": {"u@example.com"}, "password": {testPW}}); code != 403 {
		t.Errorf("login without csrf: %d", code)
	}
	for i := 0; i < 5; i++ {
		if code, _, _ := c.login("u@example.com", "bad-password-x"); code != 401 {
			t.Fatalf("attempt %d: %d", i, code)
		}
	}
	if code, _, _ := c.login("u@example.com", testPW); code != 429 {
		t.Errorf("throttled login with right password: %d", code)
	}
	// other email / other IP unaffected
	e.addAccount("v@example.com", RoleUser, 0)
	if code, _, _ := e.newClient().login("v@example.com", testPW); code != 303 {
		t.Errorf("other account: %d", code)
	}
}

func TestCSRFRejected(t *testing.T) {
	e := newEnv(t)
	e.addAccount("root@example.com", RoleSuper, 0)
	c := e.login("root@example.com")
	for _, tok := range []string{"", "wrong"} {
		code, _, _ := c.postRaw("/departments", url.Values{"name": {"Sales"}, "csrf": {tok}})
		expect(t, "csrf="+tok, code, 403)
	}
	if n := e.count(`SELECT COUNT(*) FROM departments`); n != 0 {
		t.Error("department created without valid CSRF token")
	}
	if code, _, _ := c.post("/departments", url.Values{"name": {"Sales"}}); code != 303 {
		t.Errorf("valid csrf: %d", code)
	}
}

func TestSuperadminFlow(t *testing.T) {
	e := newEnv(t)
	e.addAccount("root@example.com", RoleSuper, 0)
	c := e.login("root@example.com")
	c.post("/departments", url.Values{"name": {"Sales"}})
	dept := e.addDept("Sales")
	code, _, loc := c.post("/accounts/new", url.Values{"email": {"New.User@Example.com"}, "password": {"longenough-pw"},
		"role": {"user"}, "dept": {strconv.Itoa(int(dept))}, "quota_mb": {"500"}, "can_send": {"1"}, "keep_copy": {"1"}})
	if code != 303 {
		t.Fatalf("create account: %d", code)
	}
	a, err := loadAccountByEmail(e.db, "new.user@example.com")
	if err != nil || a.Dept != dept || a.Quota != 500 || loc != "/accounts/"+strconv.Itoa(int(a.ID))+"?msg=Account+created" {
		t.Fatalf("account: %+v %v %s", a, err, loc)
	}
	var h string
	e.db.QueryRow(`SELECT password FROM accounts WHERE id=?`, a.ID).Scan(&h)
	if !strings.HasPrefix(h, "{BLF-CRYPT}$2a$10$") || !verifyPassword(h, "longenough-pw") {
		t.Errorf("stored hash %q", h)
	}
	// duplicates, bad domain, collisions
	for name, f := range map[string]url.Values{
		"duplicate":  {"email": {"new.user@example.com"}, "password": {"longenough-pw"}, "role": {"user"}},
		"bad domain": {"email": {"x@unknown.org"}, "password": {"longenough-pw"}, "role": {"user"}},
		"short pw":   {"email": {"y@example.com"}, "password": {"short"}, "role": {"user"}},
		"bad email":  {"email": {"not an email"}, "password": {"longenough-pw"}, "role": {"user"}},
	} {
		f.Set("quota_mb", "100")
		if code, _, _ := c.post("/accounts/new", f); code != 400 {
			t.Errorf("%s: %d", name, code)
		}
	}
	// alias + collision both ways
	if code, _, _ := c.post("/aliases/new", url.Values{"address": {"Support@example.com"}, "members": {"new.user@example.com:send\next@other.org"}, "active": {"1"}, "dept": {"0"}}); code != 303 {
		t.Fatalf("create alias: %d", code)
	}
	if code, _, _ := c.post("/aliases/new", url.Values{"address": {"new.user@example.com"}, "members": {"a@example.com"}}); code != 400 {
		t.Errorf("alias equal to account: %d", code)
	}
	if code, _, _ := c.post("/accounts/new", url.Values{"email": {"support@example.com"}, "password": {"longenough-pw"}, "role": {"user"}, "quota_mb": {"1"}}); code != 400 {
		t.Errorf("account equal to alias: %d", code)
	}
	if n := e.count(`SELECT COUNT(*) FROM v_sender WHERE address='support@example.com' AND login='new.user@example.com'`); n != 1 {
		t.Error("send-as member missing from v_sender")
	}
	// pages render
	for _, p := range []string{"/", "/accounts", "/accounts/new", "/accounts/" + strconv.Itoa(int(a.ID)), "/aliases", "/aliases/new", "/aliases/1",
		"/departments", "/domains", "/dns", "/audit", "/import", "/export.csv", "/me", "/accounts?q=new&status=active"} {
		if code, _, _ := c.get(p); code != 200 {
			t.Errorf("GET %s: %d", p, code)
		}
	}
	if _, body, _ := c.get("/dns"); !strings.Contains(body, "v=DKIM1; k=rsa; p=") || !strings.Contains(body, "10 mail.example.com.") || !strings.Contains(body, "v=spf1") || !strings.Contains(body, "_dmarc.example.com.") {
		t.Error("DNS page incomplete")
	}
	// every mutation audited
	for _, act := range []string{"department.create", "account.create", "alias.create", "login"} {
		if e.count(`SELECT COUNT(*) FROM audit_log WHERE action=?`, act) == 0 {
			t.Errorf("no audit entry %s", act)
		}
	}
	// password reset kills sessions of that account
	u := e.loginPW("new.user@example.com", "longenough-pw")
	if code, _, _ := u.get("/me"); code != 200 {
		t.Fatal("user session")
	}
	c.post("/accounts/"+strconv.Itoa(int(a.ID))+"/password", url.Values{"password": {"another-long-pw"}})
	if code, _, loc := u.get("/me"); code != 303 || loc != "/login" {
		t.Errorf("session survived password reset: %d", code)
	}
}

func TestDepartmentAdminIsolation(t *testing.T) {
	e := newEnv(t)
	e.addAccount("root@example.com", RoleSuper, 0)
	sales, hr := e.addDept("Sales"), e.addDept("HR")
	e.addAccount("boss@example.com", RoleAdmin, sales)
	e.addAccount("sam@example.com", RoleUser, sales)
	e.addAccount("hana@example.com", RoleUser, hr)
	e.addAccount("hhelp@example.com", RoleHelpdesk, hr)
	e.addAccount("other-admin@example.com", RoleAdmin, hr)
	e.db.Exec(`INSERT INTO aliases(id,address,department_id) VALUES(1,'hr@example.com',?)`, hr)
	e.db.Exec(`INSERT INTO alias_members VALUES(1,'hana@example.com',0)`)
	e.db.Exec(`INSERT INTO aliases(id,address,department_id) VALUES(2,'sales@example.com',?)`, sales)
	e.db.Exec(`INSERT INTO alias_members VALUES(2,'sam@example.com',0)`)

	c := e.login("boss@example.com")
	other := strconv.Itoa(int(e.accountID("hana@example.com")))
	own := strconv.Itoa(int(e.accountID("sam@example.com")))
	hrAdmin := strconv.Itoa(int(e.accountID("other-admin@example.com")))

	// cannot see other department
	if code, _, _ := c.get("/accounts/" + other); code != 403 {
		t.Errorf("view other dept account: %d", code)
	}
	if _, body, _ := c.get("/accounts"); strings.Contains(body, "hana@") || !strings.Contains(body, "sam@") {
		t.Error("account list not scoped to department")
	}
	if code, _, _ := c.get("/aliases/1"); code != 403 {
		t.Errorf("view other dept alias: %d", code)
	}
	if _, body, _ := c.get("/aliases"); strings.Contains(body, "hr@example.com") || !strings.Contains(body, "sales@example.com") {
		t.Error("alias list not scoped")
	}
	// cannot modify other department
	for _, p := range []string{"/accounts/" + other, "/accounts/" + other + "/password", "/accounts/" + other + "/active", "/accounts/" + other + "/delete",
		"/aliases/1", "/aliases/1/delete"} {
		code, _, _ := c.post(p, url.Values{"password": {"hacked-password"}, "active": {"0"}, "name": {"x"}, "quota_mb": {"1"}, "members": {"evil@ext.org"}})
		if code != 403 {
			t.Errorf("POST %s: %d, want 403", p, code)
		}
	}
	// cannot touch an equal-rank admin, even in another department, nor superadmin
	for _, p := range []string{"/accounts/" + hrAdmin + "/password", "/accounts/" + strconv.Itoa(int(e.accountID("root@example.com"))) + "/password"} {
		if code, _, _ := c.post(p, url.Values{"password": {"hacked-password"}}); code != 403 {
			t.Errorf("POST %s: %d", p, code)
		}
	}
	// admin-only/global pages
	for _, p := range []string{"/domains", "/departments", "/dns", "/audit", "/import", "/export.csv"} {
		if code, _, _ := c.get(p); code != 403 {
			t.Errorf("GET %s: %d, want 403", p, code)
		}
	}
	for _, p := range []string{"/domains", "/departments"} {
		if code, _, _ := c.post(p, url.Values{"name": {"evil.com"}}); code != 403 {
			t.Errorf("POST %s: %d", p, code)
		}
	}
	if e.count(`SELECT COUNT(*) FROM domains`) != 1 || e.count(`SELECT COUNT(*) FROM departments`) != 2 {
		t.Error("global data changed")
	}
	var hash string
	e.db.QueryRow(`SELECT password FROM accounts WHERE id=?`, other).Scan(&hash)
	if !verifyPassword(hash, testPW) {
		t.Error("other department password changed")
	}

	// may create users in own dept only; role/dept form values are ignored
	code, _, _ := c.post("/accounts/new", url.Values{"email": {"newbie@example.com"}, "password": {"longenough-pw"},
		"role": {"superadmin"}, "dept": {strconv.Itoa(int(hr))}, "quota_mb": {"100"}})
	if code != 303 {
		t.Fatalf("create: %d", code)
	}
	n, _ := loadAccountByEmail(e.db, "newbie@example.com")
	if n.Role != RoleUser || n.Dept != sales {
		t.Errorf("created account %+v must be user in own dept", n)
	}
	// edit own-dept user: allowed, but cannot change role or department
	code, _, _ = c.post("/accounts/"+own, url.Values{"name": {"Sam"}, "quota_mb": {"777"}, "role": {"admin"}, "dept": {strconv.Itoa(int(hr))}})
	s, _ := loadAccountByEmail(e.db, "sam@example.com")
	if code != 303 || s.Quota != 777 || s.Role != RoleUser || s.Dept != sales {
		t.Errorf("edit own: %d %+v", code, s)
	}
	// own-dept alias management works; cannot move alias to other dept
	code, _, _ = c.post("/aliases/new", url.Values{"address": {"team@example.com"}, "members": {"sam@example.com"}, "dept": {strconv.Itoa(int(hr))}})
	var ad int64
	e.db.QueryRow(`SELECT department_id FROM aliases WHERE address='team@example.com'`).Scan(&ad)
	if code != 303 || ad != sales {
		t.Errorf("alias create: %d dept %d", code, ad)
	}
	// delete own-dept user
	if code, _, _ := c.post("/accounts/"+own+"/delete", nil); code != 303 {
		t.Errorf("delete own: %d", code)
	}
	if _, err := loadAccount(e.db, e.accountID0("sam@example.com")); err == nil {
		t.Error("sam still exists")
	}

	// helpdesk: sees own dept, resets user, cannot edit/delete/create, cannot touch admin
	h := e.login("hhelp@example.com")
	if code, _, _ := h.get("/accounts/" + other); code != 200 {
		t.Errorf("helpdesk view own dept: %d", code)
	}
	if code, _, _ := h.get("/accounts/new"); code != 403 {
		t.Errorf("helpdesk new: %d", code)
	}
	if code, _, _ := h.get("/aliases/new"); code != 403 {
		t.Errorf("helpdesk alias new: %d", code)
	}
	if code, _, _ := h.post("/accounts/"+other, url.Values{"name": {"x"}, "quota_mb": {"5"}}); code != 403 {
		t.Errorf("helpdesk edit: %d", code)
	}
	if code, _, _ := h.post("/accounts/"+other+"/delete", nil); code != 403 {
		t.Errorf("helpdesk delete: %d", code)
	}
	if code, _, _ := h.post("/accounts/"+hrAdmin+"/password", url.Values{"password": {"hacked-password"}}); code != 403 {
		t.Errorf("helpdesk reset admin: %d", code)
	}
	if code, _, _ := h.post("/accounts/"+other+"/password", url.Values{"password": {"fresh-password-1"}}); code != 303 {
		t.Errorf("helpdesk reset user: %d", code)
	}
	if code, _, _ := h.post("/accounts/"+other+"/active", url.Values{"active": {"0"}}); code != 303 {
		t.Errorf("helpdesk disable user: %d", code)
	}
	if e.count(`SELECT COUNT(*) FROM accounts WHERE id=? AND active=0`, other) != 1 {
		t.Error("user not disabled")
	}
	if code, _, _ := h.get("/accounts/" + own); code != 404 {
		t.Errorf("deleted/other dept: %d", code)
	}

	// plain user: no lists, no admin pages, can use /me
	u := e.loginPW("newbie@example.com", "longenough-pw")
	for _, p := range []string{"/accounts", "/aliases", "/accounts/new", "/domains"} {
		if code, _, _ := u.get(p); code != 403 {
			t.Errorf("user GET %s: %d", p, code)
		}
	}
	if code, _, _ := u.get("/me"); code != 200 {
		t.Error("user /me")
	}
	if code, _, _ := u.post("/me/forward", url.Values{"forward_to": {"a@ext.org"}}); code != 403 {
		t.Errorf("forward disabled by default: %d", code)
	}
	e.app.cfg.AllowUserForward = true
	if code, _, _ := u.post("/me/forward", url.Values{"forward_to": {"a@ext.org, b@ext.org"}, "keep_copy": {"1"}}); code != 303 {
		t.Errorf("forward allowed: %d", code)
	}
	if f, _ := loadAccountByEmail(e.db, "newbie@example.com"); f.Forward != "a@ext.org,b@ext.org" {
		t.Errorf("forward stored %q", f.Forward)
	}
	// own password change needs current password and ends sessions
	if code, _, loc := u.post("/me/password", url.Values{"current": {"nope"}, "new": {"brand-new-password"}, "confirm": {"brand-new-password"}}); code != 303 || strings.HasPrefix(loc, "/login") {
		t.Errorf("wrong current: %d %s", code, loc)
	}
	if code, _, loc := u.post("/me/password", url.Values{"current": {"longenough-pw"}, "new": {"brand-new-password"}, "confirm": {"brand-new-password"}}); code != 303 || !strings.HasPrefix(loc, "/login") {
		t.Errorf("change password: %d %s", code, loc)
	}
	if code, _, _ := u.get("/me"); code != 303 {
		t.Error("session must be gone after password change")
	}
}

func (e *testEnv) accountID0(email string) int64 {
	var id int64
	e.db.QueryRow(`SELECT id FROM accounts WHERE email=?`, email).Scan(&id)
	return id
}

func TestLastSuperadminGuard(t *testing.T) {
	e := newEnv(t)
	e.addAccount("root@example.com", RoleSuper, 0)
	c := e.login("root@example.com")
	id := strconv.Itoa(int(e.accountID("root@example.com")))
	for name, p := range map[string]url.Values{"/accounts/" + id + "/delete": nil, "/accounts/" + id + "/active": {"active": {"0"}},
		"/accounts/" + id: {"role": {"admin"}, "quota_mb": {"10"}, "dept": {"0"}}} {
		if code, _, _ := c.post(name, p); code != 400 {
			t.Errorf("POST %s: %d, want 400", name, code)
		}
	}
	if a, _ := loadAccountByEmail(e.db, "root@example.com"); a.Role != RoleSuper || !a.Active {
		t.Errorf("last superadmin changed: %+v", a)
	}
	// with a second superadmin the first can be demoted
	e.addAccount("root2@example.com", RoleSuper, 0)
	if code, _, _ := c.post("/accounts/"+id, url.Values{"role": {"admin"}, "quota_mb": {"10"}, "dept": {"0"}}); code != 303 {
		t.Errorf("demote with 2 supers: %d", code)
	}
}

func TestImportHandlerAndCredentialsCSV(t *testing.T) {
	e := newEnv(t)
	e.addAccount("root@example.com", RoleSuper, 0)
	c := e.login("root@example.com")
	// multipart upload through the real handler
	body, ctype := multipartFile("file", "in.csv", goodCSV, c.csrf)
	req := newReq(c, "/import", body, ctype)
	code, out, _ := c.do(req)
	if code != 200 || !strings.HasPrefix(out, "email,password\n") || strings.Count(out, "\n") != 3 {
		t.Fatalf("import: %d %q", code, out)
	}
	if e.count(`SELECT COUNT(*) FROM accounts`) != 3 {
		t.Error("accounts missing")
	}
}
