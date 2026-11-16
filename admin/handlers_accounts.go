package main

import (
	"database/sql"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var errForbidden = errors.New("forbidden")

// ---- login / logout ----

const loginCookie = "rm_login"

func (a *App) loginPage(w http.ResponseWriter, r *http.Request) {
	c := &Ctx{A: a, W: w, R: r, IP: clientIP(r)}
	tok := randToken(16)
	a.setCookie(w, loginCookie, tok, 900)
	c.render("login", map[string]any{"Title": "Log in", "LoginCSRF": tok})
}

func (a *App) loginPost(w http.ResponseWriter, r *http.Request) {
	c := &Ctx{A: a, W: w, R: r, IP: clientIP(r)}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	ck, err := r.Cookie(loginCookie)
	if err != nil || !tokenEq(r.PostFormValue("csrf"), ck.Value) {
		c.status(http.StatusForbidden, "Invalid or missing CSRF token. Reload the login page.")
		return
	}
	email := strings.ToLower(strings.TrimSpace(r.PostFormValue("email")))
	pw := r.PostFormValue("password")
	key := c.IP + "|" + email
	again := func(code int, msg string) {
		tok := randToken(16)
		a.setCookie(w, loginCookie, tok, 900)
		c.renderStatus(code, "login", map[string]any{"Title": "Log in", "LoginCSRF": tok, "Err": msg, "Email": email})
	}
	if a.throttle.blocked(key) {
		again(http.StatusTooManyRequests, "Too many failed attempts. Try again in 15 minutes.")
		return
	}
	var id int64
	var stored string
	err = a.db.QueryRow(`SELECT id,password FROM accounts WHERE email=? AND active=1`, email).Scan(&id, &stored)
	if err != nil {
		stored = a.dummyHash // constant work for unknown users
	}
	if !verifyPassword(stored, pw) || err != nil {
		a.throttle.fail(key)
		again(http.StatusUnauthorized, "Wrong email or password.")
		return
	}
	a.throttle.reset(key)
	tok, csrf := randToken(32), randToken(16)
	exp := time.Now().UTC().Add(time.Duration(a.cfg.SessionHours) * time.Hour).Format("2006-01-02 15:04:05")
	err = tx(a.db, func(t *sql.Tx) error {
		t.Exec(`DELETE FROM sessions WHERE expires_at<=datetime('now')`)
		if _, err := t.Exec(`INSERT INTO sessions(token_hash,account_id,csrf,expires_at) VALUES(?,?,?,?)`, sha(tok), id, csrf, exp); err != nil {
			return err
		}
		audit(t, email, "login", email, "", c.IP)
		return nil
	})
	if err != nil {
		c.fail(err)
		return
	}
	a.setCookie(w, loginCookie, "", -1)
	a.setCookie(w, sessionCookie, tok, a.cfg.SessionHours*3600)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (c *Ctx) logout() {
	if ck, err := c.R.Cookie(sessionCookie); err == nil {
		c.A.db.Exec(`DELETE FROM sessions WHERE token_hash=?`, sha(ck.Value))
	}
	c.A.setCookie(c.W, sessionCookie, "", -1)
	c.loginRedirect()
}

// ---- dashboard ----

func (c *Ctx) dashboard() {
	all, dept, ok := ListScope(c.U)
	count := func(table string) int {
		var n int
		switch {
		case all:
			c.A.db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n)
		case ok:
			c.A.db.QueryRow(`SELECT COUNT(*) FROM `+table+` WHERE department_id=?`, dept).Scan(&n)
		}
		return n
	}
	d := map[string]any{"Title": "Dashboard", "Accounts": count("accounts"), "Aliases": count("aliases")}
	if all {
		var act, dom, dep int
		c.A.db.QueryRow(`SELECT COUNT(*) FROM accounts WHERE active=1`).Scan(&act)
		c.A.db.QueryRow(`SELECT COUNT(*) FROM domains`).Scan(&dom)
		c.A.db.QueryRow(`SELECT COUNT(*) FROM departments`).Scan(&dep)
		d["Active"], d["Domains"], d["Depts"] = act, dom, dep
	}
	c.render("dashboard", d)
}

// ---- accounts ----

const pageSize = 50

func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

func (c *Ctx) accountList() {
	all, dept, ok := ListScope(c.U)
	if !ok {
		c.forbidden()
		return
	}
	qv := c.R.URL.Query()
	q, st := strings.TrimSpace(qv.Get("q")), qv.Get("status")
	fd, _ := strconv.ParseInt(qv.Get("dept"), 10, 64)
	page, _ := strconv.Atoi(qv.Get("page"))
	if page < 1 {
		page = 1
	}
	where, args := []string{"1=1"}, []any{}
	if !all {
		where, args = append(where, "a.department_id=?"), append(args, dept)
	} else if fd > 0 {
		where, args = append(where, "a.department_id=?"), append(args, fd)
	}
	if q != "" {
		l := "%" + escapeLike(q) + "%"
		where, args = append(where, `(a.email LIKE ? ESCAPE '\' OR a.name LIKE ? ESCAPE '\')`), append(args, l, l)
	}
	switch st {
	case "active":
		where = append(where, "a.active=1")
	case "disabled":
		where = append(where, "a.active=0")
	}
	w := strings.Join(where, " AND ")
	var total int
	c.A.db.QueryRow(`SELECT COUNT(*)`+accountFrom+`WHERE `+w, args...).Scan(&total)
	rows, err := c.A.db.Query(`SELECT `+accountCols+accountFrom+`WHERE `+w+` ORDER BY a.email LIMIT ? OFFSET ?`,
		append(args, pageSize, (page-1)*pageSize)...)
	if err != nil {
		c.fail(err)
		return
	}
	defer rows.Close()
	var list []Account
	for rows.Next() {
		a, err := scanAccount(rows)
		if err != nil {
			c.fail(err)
			return
		}
		list = append(list, a)
	}
	depts, _ := listDepts(c.A.db)
	base := url.Values{"q": {q}, "dept": {qv.Get("dept")}, "status": {st}}
	c.render("accounts", map[string]any{"Title": "Accounts", "List": list, "Total": total, "Q": q, "Status": st, "FilterDept": fd,
		"Depts": depts, "Page": page, "Prev": page - 1, "Next": page + 1, "HasNext": page*pageSize < total,
		"Base": base.Encode(), "CanCreate": c.U.Role == RoleSuper || c.U.Role == RoleAdmin, "Super": all})
}

type accountForm struct {
	acc  *Account
	form url.Values
	err  string
}

func (c *Ctx) accountPage(code int, f accountForm) {
	depts, _ := listDepts(c.A.db)
	d := map[string]any{"Title": "New account", "Form": f.form, "Depts": depts, "Err": f.err,
		"CanRole": CanChangeRoleOrDept(c.U), "Roles": []string{RoleUser, RoleHelpdesk, RoleAdmin, RoleSuper}, "OwnDept": c.U.Dept}
	for _, x := range depts {
		if x.ID == c.U.Dept {
			d["OwnDeptName"] = x.Name
		}
	}
	if f.acc != nil {
		t := f.acc.Target()
		d["Title"], d["Acc"] = f.acc.Email, f.acc
		d["CanEdit"] = CanEditAccount(c.U, t)
		d["CanReset"] = CanResetPassword(c.U, t)
		d["CanActive"] = CanSetActive(c.U, t)
		d["CanDelete"] = CanDeleteAccount(c.U, t)
	}
	c.renderStatus(code, "account", d)
}

func accountValues(a Account) url.Values {
	v := url.Values{"email": {a.Email}, "name": {a.Name}, "role": {a.Role}, "dept": {strconv.FormatInt(a.Dept, 10)},
		"quota_mb": {strconv.Itoa(a.Quota)}, "forward_to": {strings.ReplaceAll(a.Forward, ",", ", ")}}
	if a.CanSend {
		v.Set("can_send", "1")
	}
	if a.KeepCopy {
		v.Set("keep_copy", "1")
	}
	return v
}

func (c *Ctx) accountNew() {
	if !CanCreateAccount(c.U, Target{RoleUser, c.U.Dept}) {
		c.forbidden()
		return
	}
	c.accountPage(200, accountForm{form: url.Values{"role": {RoleUser}, "can_send": {"1"}, "keep_copy": {"1"},
		"quota_mb": {strconv.Itoa(c.A.cfg.DefaultQuota)}}})
}

func (c *Ctx) accountView() {
	id, ok := c.id()
	if !ok {
		c.notFound()
		return
	}
	acc, err := loadAccount(c.A.db, id)
	if err != nil {
		c.fail(err)
		return
	}
	if !CanList(c.U, acc.Dept) {
		c.forbidden()
		return
	}
	c.accountPage(200, accountForm{acc: &acc, form: accountValues(acc)})
}

func (c *Ctx) secret(email, pw, back string) {
	c.render("secret", map[string]any{"Title": "Password", "Email": email, "Password": pw, "Back": back})
}

func (c *Ctx) accountCreate() {
	in := AccIn{Email: c.form("email"), Name: c.form("name"), Role: c.form("role"), Dept: c.formID("dept"),
		Quota: c.formInt("quota_mb", c.A.cfg.DefaultQuota), CanSend: c.checked("can_send"),
		Forward: c.form("forward_to"), KeepCopy: c.checked("keep_copy")}
	if !CanChangeRoleOrDept(c.U) { // department admins create plain users in their own department
		in.Role, in.Dept = RoleUser, c.U.Dept
	}
	if !CanCreateAccount(c.U, Target{in.Role, in.Dept}) {
		c.forbidden()
		return
	}
	gen := c.checked("generate")
	pw := c.R.PostFormValue("password")
	if gen {
		pw = genPassword()
	}
	err := checkPassword(pw)
	var hash string
	if err == nil {
		hash, err = hashPassword(pw)
	}
	var id int64
	if err == nil {
		err = tx(c.A.db, func(t *sql.Tx) error {
			if err := in.normalize(t, true); err != nil {
				return err
			}
			var err error
			if id, err = insertAccount(t, in, hash); err != nil {
				return err
			}
			c.audit(t, "account.create", in.Email, "role="+in.Role)
			return nil
		})
	}
	if err != nil {
		if ue, ok := err.(userErr); ok {
			c.accountPage(http.StatusBadRequest, accountForm{form: c.R.PostForm, err: string(ue)})
			return
		}
		c.fail(err)
		return
	}
	back := "/accounts/" + strconv.FormatInt(id, 10)
	if gen {
		c.secret(in.Email, pw, back)
		return
	}
	c.redirect(back, "Account created")
}

func (c *Ctx) accountUpdate() {
	id, ok := c.id()
	if !ok {
		c.notFound()
		return
	}
	var cur Account
	err := tx(c.A.db, func(t *sql.Tx) error {
		var err error
		if cur, err = loadAccount(t, id); err != nil {
			return err
		}
		if !CanEditAccount(c.U, cur.Target()) {
			return errForbidden
		}
		in := AccIn{Email: cur.Email, Name: c.form("name"), Role: cur.Role, Dept: cur.Dept,
			Quota: c.formInt("quota_mb", cur.Quota), CanSend: c.checked("can_send"),
			Forward: c.form("forward_to"), KeepCopy: c.checked("keep_copy")}
		if CanChangeRoleOrDept(c.U) {
			in.Role, in.Dept = c.form("role"), c.formID("dept")
		}
		if err := in.normalize(t, false); err != nil {
			return err
		}
		if err := guardLastSuper(t, cur, in.Role, cur.Active, false); err != nil {
			return bad("%s", err)
		}
		if err := updateAccount(t, id, in); err != nil {
			return err
		}
		c.audit(t, "account.update", cur.Email, "role="+in.Role)
		return nil
	})
	c.done(err, "/accounts/"+strconv.FormatInt(id, 10), "Saved", func(msg string) {
		c.accountPage(http.StatusBadRequest, accountForm{acc: &cur, form: c.R.PostForm, err: msg})
	})
}

// done finishes a mutation: redirect on success, re-render on user errors.
func (c *Ctx) done(err error, to, msg string, rerender func(string)) {
	switch ue, isUser := err.(userErr); {
	case err == nil:
		c.redirect(to, msg)
	case err == errForbidden:
		c.forbidden()
	case isUser && rerender != nil:
		rerender(string(ue))
	default:
		c.fail(err)
	}
}

func (c *Ctx) accountPassword() {
	id, ok := c.id()
	if !ok {
		c.notFound()
		return
	}
	gen := c.checked("generate")
	pw := c.R.PostFormValue("password")
	if gen {
		pw = genPassword()
	}
	var cur Account
	err := checkPassword(pw)
	var hash string
	if err == nil {
		hash, err = hashPassword(pw)
	}
	if err == nil {
		err = tx(c.A.db, func(t *sql.Tx) error {
			var err error
			if cur, err = loadAccount(t, id); err != nil {
				return err
			}
			if !CanResetPassword(c.U, cur.Target()) {
				return errForbidden
			}
			if _, err := t.Exec(`UPDATE accounts SET password=?,updated_at=datetime('now') WHERE id=?`, hash, id); err != nil {
				return err
			}
			killSessions(t, id)
			c.audit(t, "account.password", cur.Email, "")
			return nil
		})
	}
	back := "/accounts/" + strconv.FormatInt(id, 10)
	if err == nil && gen {
		c.secret(cur.Email, pw, back)
		return
	}
	c.done(err, back, "Password changed", nil)
}

func (c *Ctx) accountActive() {
	id, ok := c.id()
	if !ok {
		c.notFound()
		return
	}
	want := c.form("active") == "1"
	err := tx(c.A.db, func(t *sql.Tx) error {
		cur, err := loadAccount(t, id)
		if err != nil {
			return err
		}
		if !CanSetActive(c.U, cur.Target()) {
			return errForbidden
		}
		if err := guardLastSuper(t, cur, cur.Role, want, false); err != nil {
			return bad("%s", err)
		}
		if _, err := t.Exec(`UPDATE accounts SET active=?,updated_at=datetime('now') WHERE id=?`, want, id); err != nil {
			return err
		}
		act := "account.enable"
		if !want {
			killSessions(t, id)
			act = "account.disable"
		}
		c.audit(t, act, cur.Email, "")
		return nil
	})
	back := "/accounts/" + strconv.FormatInt(id, 10)
	c.done(err, back, "Saved", nil)
}

func (c *Ctx) accountDelete() {
	id, ok := c.id()
	if !ok {
		c.notFound()
		return
	}
	err := tx(c.A.db, func(t *sql.Tx) error {
		cur, err := loadAccount(t, id)
		if err != nil {
			return err
		}
		if !CanDeleteAccount(c.U, cur.Target()) {
			return errForbidden
		}
		if err := guardLastSuper(t, cur, cur.Role, cur.Active, true); err != nil {
			return bad("%s", err)
		}
		if _, err := t.Exec(`DELETE FROM accounts WHERE id=?`, id); err != nil {
			return err
		}
		c.audit(t, "account.delete", cur.Email, "")
		return nil
	})
	c.done(err, "/accounts", "Account deleted", nil)
}

// ---- my account ----

func (c *Ctx) mePage() {
	acc, err := loadAccount(c.A.db, c.U.ID)
	if err != nil {
		c.fail(err)
		return
	}
	c.render("me", map[string]any{"Title": "My account", "Acc": acc, "Form": accountValues(acc),
		"CanForward": CanChangeOwnForward(c.U, c.A.cfg.AllowUserForward)})
}

func (c *Ctx) mePassword() {
	if !CanChangeOwnPassword(c.U) {
		c.forbidden()
		return
	}
	var stored string
	c.A.db.QueryRow(`SELECT password FROM accounts WHERE id=?`, c.U.ID).Scan(&stored)
	pw := c.R.PostFormValue("new")
	var hash string
	err := error(nil)
	switch {
	case !verifyPassword(stored, c.R.PostFormValue("current")):
		err = bad("current password is wrong")
	case pw != c.R.PostFormValue("confirm"):
		err = bad("new passwords do not match")
	default:
		if err = checkPassword(pw); err == nil {
			hash, err = hashPassword(pw)
		}
	}
	if err == nil {
		err = tx(c.A.db, func(t *sql.Tx) error {
			if _, err := t.Exec(`UPDATE accounts SET password=?,updated_at=datetime('now') WHERE id=?`, hash, c.U.ID); err != nil {
				return err
			}
			killSessions(t, c.U.ID)
			c.audit(t, "account.password", c.U.Email, "self")
			return nil
		})
	}
	if err != nil {
		if ue, ok := err.(userErr); ok {
			c.redirect("/me", string(ue))
			return
		}
		c.fail(err)
		return
	}
	c.A.setCookie(c.W, sessionCookie, "", -1)
	c.redirect("/login", "Password changed, please log in again")
}

func (c *Ctx) meForward() {
	if !CanChangeOwnForward(c.U, c.A.cfg.AllowUserForward) {
		c.forbidden()
		return
	}
	err := tx(c.A.db, func(t *sql.Tx) error {
		f, err := normForward(c.form("forward_to"), c.U.Email)
		if err != nil {
			return err
		}
		if _, err := t.Exec(`UPDATE accounts SET forward_to=?,keep_copy=?,updated_at=datetime('now') WHERE id=?`, f, c.checked("keep_copy"), c.U.ID); err != nil {
			return err
		}
		c.audit(t, "account.forward", c.U.Email, f)
		return nil
	})
	c.done(err, "/me", "Saved", nil)
}
