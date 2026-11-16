package main

import (
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// ---- aliases ----

func (c *Ctx) aliasList() {
	all, dept, ok := ListScope(c.U)
	if !ok {
		c.forbidden()
		return
	}
	qv := c.R.URL.Query()
	q := strings.TrimSpace(qv.Get("q"))
	page, _ := strconv.Atoi(qv.Get("page"))
	if page < 1 {
		page = 1
	}
	where, args := []string{"1=1"}, []any{}
	if !all {
		where, args = append(where, "a.department_id=?"), append(args, dept)
	}
	if q != "" {
		l := "%" + escapeLike(q) + "%"
		where, args = append(where, `(a.address LIKE ? ESCAPE '\' OR a.description LIKE ? ESCAPE '\')`), append(args, l, l)
	}
	w := strings.Join(where, " AND ")
	var total int
	c.A.db.QueryRow(`SELECT COUNT(*)`+aliasFrom+`WHERE `+w, args...).Scan(&total)
	rows, err := c.A.db.Query(`SELECT `+aliasCols+`,(SELECT GROUP_CONCAT(destination,', ') FROM alias_members WHERE alias_id=a.id)`+
		aliasFrom+`WHERE `+w+` ORDER BY a.address LIMIT ? OFFSET ?`, append(args, pageSize, (page-1)*pageSize)...)
	if err != nil {
		c.fail(err)
		return
	}
	defer rows.Close()
	type row struct {
		Alias
		Members string
	}
	var list []row
	for rows.Next() {
		var r row
		var m sql.NullString
		if err := rows.Scan(&r.ID, &r.Address, &r.Desc, &r.Dept, &r.DeptName, &r.Active, &r.Created, &m); err != nil {
			c.fail(err)
			return
		}
		r.Members = m.String
		list = append(list, r)
	}
	c.render("aliases", map[string]any{"Title": "Aliases", "List": list, "Total": total, "Q": q, "Page": page,
		"Prev": page - 1, "Next": page + 1, "HasNext": page*pageSize < total,
		"Base": url.Values{"q": {q}}.Encode(), "CanCreate": CanManageAlias(c.U, c.U.Dept)})
}

func (c *Ctx) aliasPage(code int, al *Alias, form url.Values, errMsg string) {
	depts, _ := listDepts(c.A.db)
	d := map[string]any{"Title": "New alias", "Form": form, "Depts": depts, "Err": errMsg,
		"CanDept": CanChangeRoleOrDept(c.U), "CanManage": true}
	for _, x := range depts {
		if x.ID == c.U.Dept {
			d["OwnDeptName"] = x.Name
		}
	}
	if al != nil {
		d["Title"], d["Alias"], d["CanManage"] = al.Address, al, CanManageAlias(c.U, al.Dept)
	}
	c.renderStatus(code, "alias", d)
}

func aliasValues(a Alias) url.Values {
	v := url.Values{"address": {a.Address}, "description": {a.Desc}, "dept": {strconv.FormatInt(a.Dept, 10)}, "members": {membersText(a.Members)}}
	if a.Active {
		v.Set("active", "1")
	}
	return v
}

func (c *Ctx) aliasNew() {
	if !CanManageAlias(c.U, c.U.Dept) {
		c.forbidden()
		return
	}
	c.aliasPage(200, nil, url.Values{"active": {"1"}}, "")
}

func (c *Ctx) aliasView() {
	id, ok := c.id()
	if !ok {
		c.notFound()
		return
	}
	al, err := loadAlias(c.A.db, id)
	if err != nil {
		c.fail(err)
		return
	}
	if !CanList(c.U, al.Dept) {
		c.forbidden()
		return
	}
	c.aliasPage(200, &al, aliasValues(al), "")
}

func (c *Ctx) aliasCreate() {
	dept := c.formID("dept")
	if !CanChangeRoleOrDept(c.U) {
		dept = c.U.Dept
	}
	if !CanManageAlias(c.U, dept) {
		c.forbidden()
		return
	}
	var id int64
	err := tx(c.A.db, func(t *sql.Tx) error {
		addr, err := checkAliasAddress(t, c.form("address"))
		if err != nil {
			return err
		}
		if dept != 0 && !exists(t, `SELECT 1 FROM departments WHERE id=?`, dept) {
			return bad("unknown department")
		}
		if exists(t, `SELECT 1 FROM aliases WHERE address=?`, addr) {
			return bad("%s already exists", addr)
		}
		ms, err := parseMembers(t, addr, c.R.PostFormValue("members"))
		if err != nil {
			return err
		}
		r, err := t.Exec(`INSERT INTO aliases(address,description,department_id,active) VALUES(?,?,?,?)`,
			addr, c.form("description"), deptOrNil(dept), c.checked("active"))
		if err != nil {
			return err
		}
		id, _ = r.LastInsertId()
		if err := setMembers(t, id, ms); err != nil {
			return err
		}
		c.audit(t, "alias.create", addr, membersText(ms))
		return nil
	})
	c.done(err, "/aliases/"+strconv.FormatInt(id, 10), "Alias created", func(msg string) {
		c.aliasPage(http.StatusBadRequest, nil, c.R.PostForm, msg)
	})
}

func (c *Ctx) aliasUpdate() {
	id, ok := c.id()
	if !ok {
		c.notFound()
		return
	}
	var cur Alias
	err := tx(c.A.db, func(t *sql.Tx) error {
		var err error
		if cur, err = loadAlias(t, id); err != nil {
			return err
		}
		if !CanManageAlias(c.U, cur.Dept) {
			return errForbidden
		}
		dept := cur.Dept
		if CanChangeRoleOrDept(c.U) {
			dept = c.formID("dept")
			if dept != 0 && !exists(t, `SELECT 1 FROM departments WHERE id=?`, dept) {
				return bad("unknown department")
			}
		}
		ms, err := parseMembers(t, cur.Address, c.R.PostFormValue("members"))
		if err != nil {
			return err
		}
		if _, err := t.Exec(`UPDATE aliases SET description=?,department_id=?,active=? WHERE id=?`,
			c.form("description"), deptOrNil(dept), c.checked("active"), id); err != nil {
			return err
		}
		if err := setMembers(t, id, ms); err != nil {
			return err
		}
		c.audit(t, "alias.update", cur.Address, membersText(ms))
		return nil
	})
	c.done(err, "/aliases/"+strconv.FormatInt(id, 10), "Saved", func(msg string) {
		c.aliasPage(http.StatusBadRequest, &cur, c.R.PostForm, msg)
	})
}

func (c *Ctx) aliasDelete() {
	id, ok := c.id()
	if !ok {
		c.notFound()
		return
	}
	err := tx(c.A.db, func(t *sql.Tx) error {
		cur, err := loadAlias(t, id)
		if err != nil {
			return err
		}
		if !CanManageAlias(c.U, cur.Dept) {
			return errForbidden
		}
		if _, err := t.Exec(`DELETE FROM aliases WHERE id=?`, id); err != nil {
			return err
		}
		c.audit(t, "alias.delete", cur.Address, "")
		return nil
	})
	c.done(err, "/aliases", "Alias deleted", nil)
}

// ---- departments (superadmin) ----

func (c *Ctx) needGlobal() bool {
	if !CanGlobalAdmin(c.U) {
		c.forbidden()
		return false
	}
	return true
}

func (c *Ctx) deptList() {
	if !c.needGlobal() {
		return
	}
	l, err := listDepts(c.A.db)
	if err != nil {
		c.fail(err)
		return
	}
	c.render("departments", map[string]any{"Title": "Departments", "List": l})
}

func checkDeptName(n string) error {
	if n == "" || len(n) > 60 {
		return bad("department name must be 1-60 characters")
	}
	return nil
}

func (c *Ctx) deptCreate() {
	if !c.needGlobal() {
		return
	}
	n := c.form("name")
	err := checkDeptName(n)
	if err == nil {
		err = tx(c.A.db, func(t *sql.Tx) error {
			if exists(t, `SELECT 1 FROM departments WHERE name=?`, n) {
				return bad("department %q already exists", n)
			}
			if _, err := t.Exec(`INSERT INTO departments(name) VALUES(?)`, n); err != nil {
				return err
			}
			c.audit(t, "department.create", n, "")
			return nil
		})
	}
	c.done(err, "/departments", "Department created", nil)
}

func (c *Ctx) deptRename() {
	if !c.needGlobal() {
		return
	}
	id, _ := c.id()
	n := c.form("name")
	err := checkDeptName(n)
	if err == nil {
		err = tx(c.A.db, func(t *sql.Tx) error {
			var old string
			if t.QueryRow(`SELECT name FROM departments WHERE id=?`, id).Scan(&old) != nil {
				return errNotFound
			}
			if exists(t, `SELECT 1 FROM departments WHERE name=? AND id<>?`, n, id) {
				return bad("department %q already exists", n)
			}
			if _, err := t.Exec(`UPDATE departments SET name=? WHERE id=?`, n, id); err != nil {
				return err
			}
			c.audit(t, "department.rename", old, n)
			return nil
		})
	}
	c.done(err, "/departments", "Saved", nil)
}

func (c *Ctx) deptDelete() {
	if !c.needGlobal() {
		return
	}
	id, _ := c.id()
	err := tx(c.A.db, func(t *sql.Tx) error {
		var n string
		if t.QueryRow(`SELECT name FROM departments WHERE id=?`, id).Scan(&n) != nil {
			return errNotFound
		}
		if _, err := t.Exec(`DELETE FROM departments WHERE id=?`, id); err != nil {
			return err
		}
		c.audit(t, "department.delete", n, "")
		return nil
	})
	c.done(err, "/departments", "Department deleted", nil)
}

// ---- domains (superadmin) ----

func (c *Ctx) domainList() {
	if !c.needGlobal() {
		return
	}
	rows, err := c.A.db.Query(`SELECT d.name,d.created_at,
		(SELECT COUNT(*) FROM accounts WHERE email LIKE '%@'||d.name),
		(SELECT COUNT(*) FROM aliases WHERE address LIKE '%@'||d.name) FROM domains d ORDER BY d.name`)
	if err != nil {
		c.fail(err)
		return
	}
	defer rows.Close()
	type dom struct {
		Name, Created     string
		Accounts, Aliases int
	}
	var l []dom
	for rows.Next() {
		var d dom
		rows.Scan(&d.Name, &d.Created, &d.Accounts, &d.Aliases)
		l = append(l, d)
	}
	c.render("domains", map[string]any{"Title": "Domains", "List": l, "Primary": c.A.cfg.PrimaryDomain})
}

func (c *Ctx) domainCreate() {
	if !c.needGlobal() {
		return
	}
	d, err := normDomain(c.form("name"))
	if err == nil {
		err = tx(c.A.db, func(t *sql.Tx) error {
			if exists(t, `SELECT 1 FROM domains WHERE name=?`, d) {
				return bad("domain %q already exists", d)
			}
			if err := ensureDomain(t, d); err != nil {
				return err
			}
			if err := ensureDKIM(c.A.cfg.DKIMDir, d); err != nil {
				return err
			}
			c.audit(t, "domain.create", d, "")
			return nil
		})
	}
	c.done(err, "/domains", "Domain added; publish its DNS records", nil)
}

func (c *Ctx) domainDelete() {
	if !c.needGlobal() {
		return
	}
	d := c.R.PathValue("name")
	err := tx(c.A.db, func(t *sql.Tx) error {
		if d == c.A.cfg.PrimaryDomain {
			return bad("the primary domain cannot be removed")
		}
		if exists(t, `SELECT 1 FROM accounts WHERE email LIKE '%@'||?`, d) || exists(t, `SELECT 1 FROM aliases WHERE address LIKE '%@'||?`, d) {
			return bad("domain %q still has accounts or aliases", d)
		}
		r, err := t.Exec(`DELETE FROM domains WHERE name=?`, d)
		if err != nil {
			return err
		}
		if n, _ := r.RowsAffected(); n == 0 {
			return errNotFound
		}
		c.audit(t, "domain.delete", d, "")
		return nil
	})
	c.done(err, "/domains", "Domain removed", nil)
}

// ---- DNS ----

type DNSRecord struct{ Name, Type, Value string }

type DNSDomain struct {
	Name    string
	Records []DNSRecord
	Err     string
}

func (c *Ctx) dnsPage() {
	if !c.needGlobal() {
		return
	}
	rows, err := c.A.db.Query(`SELECT name FROM domains ORDER BY name`)
	if err != nil {
		c.fail(err)
		return
	}
	var names []string
	for rows.Next() {
		var n string
		rows.Scan(&n)
		names = append(names, n)
	}
	rows.Close()
	var out []DNSDomain
	for _, n := range names {
		host := c.A.cfg.MailHost
		if host == "" {
			host = "mail." + n
		}
		d := DNSDomain{Name: n}
		pub, err := "", ensureDKIM(c.A.cfg.DKIMDir, n)
		if err == nil {
			pub, err = dkimPublic(c.A.cfg.DKIMDir, n)
		}
		d.Records = []DNSRecord{
			{n + ".", "MX", "10 " + host + "."},
			{n + ".", "TXT", "v=spf1 mx ~all"},
		}
		if err != nil {
			d.Err = "DKIM key unavailable: " + err.Error()
		} else {
			d.Records = append(d.Records, DNSRecord{"mail._domainkey." + n + ".", "TXT", "v=DKIM1; k=rsa; p=" + pub})
		}
		d.Records = append(d.Records, DNSRecord{"_dmarc." + n + ".", "TXT", "v=DMARC1; p=none; adkim=r; aspf=r"})
		out = append(out, d)
	}
	host := c.A.cfg.MailHost
	c.render("dns", map[string]any{"Title": "DNS records", "Domains": out, "MailHost": host})
}

// ---- audit ----

func (c *Ctx) auditPage() {
	if !c.needGlobal() {
		return
	}
	page, _ := strconv.Atoi(c.R.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	var total int
	c.A.db.QueryRow(`SELECT COUNT(*) FROM audit_log`).Scan(&total)
	rows, err := c.A.db.Query(`SELECT at,actor,action,target,detail,ip FROM audit_log ORDER BY id DESC LIMIT ? OFFSET ?`, pageSize, (page-1)*pageSize)
	if err != nil {
		c.fail(err)
		return
	}
	defer rows.Close()
	type ent struct{ At, Actor, Action, Target, Detail, IP string }
	var l []ent
	for rows.Next() {
		var e ent
		rows.Scan(&e.At, &e.Actor, &e.Action, &e.Target, &e.Detail, &e.IP)
		l = append(l, e)
	}
	c.render("audit", map[string]any{"Title": "Audit log", "List": l, "Page": page, "Prev": page - 1, "Next": page + 1,
		"HasNext": page*pageSize < total, "Base": ""})
}

// ---- CSV import / export (superadmin) ----

func (c *Ctx) importPage() {
	if !c.needGlobal() {
		return
	}
	c.render("import", map[string]any{"Title": "Import / export", "Header": strings.Join(csvHeader, ",")})
}

func (c *Ctx) importPost() {
	if !c.needGlobal() {
		return
	}
	data := map[string]any{"Title": "Import / export", "Header": strings.Join(csvHeader, ",")}
	f, _, err := c.R.FormFile("file")
	if err != nil {
		data["Err"] = "Choose a CSV file."
		c.renderStatus(http.StatusBadRequest, "import", data)
		return
	}
	defer f.Close()
	res, err := importCSV(c.A.db, io.Reader(f), c.U.Email, c.IP, c.A.cfg.DefaultQuota)
	if ue, ok := err.(userErr); ok {
		data["Err"] = string(ue)
		c.renderStatus(http.StatusBadRequest, "import", data)
		return
	}
	if err != nil {
		c.fail(err)
		return
	}
	if len(res.Errors) > 0 {
		data["Err"] = "Nothing was imported. Fix these lines and upload again."
		data["Errors"] = res.Errors
		c.renderStatus(http.StatusUnprocessableEntity, "import", data)
		return
	}
	if len(res.Creds) > 0 { // shown once: credentials of new mailboxes
		c.W.Header().Set("Content-Type", "text/csv; charset=utf-8")
		c.W.Header().Set("Content-Disposition", `attachment; filename="credentials.csv"`)
		c.W.Write(credsCSV(res.Creds))
		return
	}
	data["Msg"] = fmt.Sprintf("Imported: %d created, %d updated.", res.Created, res.Updated)
	c.render("import", data)
}

func (c *Ctx) exportGet() {
	if !c.needGlobal() {
		return
	}
	c.W.Header().Set("Content-Type", "text/csv; charset=utf-8")
	c.W.Header().Set("Content-Disposition", `attachment; filename="rokmail-export.csv"`)
	if err := exportCSV(c.A.db, c.W); err != nil {
		fmt.Println("export:", err)
	}
	// audit exports too
	audit(c.A.db, c.U.Email, "csv.export", "", "", c.IP)
}
