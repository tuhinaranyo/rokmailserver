package main

import (
	"bytes"
	"database/sql"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

var csvHeader = []string{"email", "name", "type", "department", "quota_mb", "forward_to", "members", "role"}

type ImportResult struct {
	Created, Updated int
	Errors           []string   // "line N: message"
	Creds            [][]string // email, password of newly created mailboxes
	newMailboxes     []string
}

type csvRow struct {
	line int
	f    map[string]string
}

var errInvalidImport = errors.New("invalid import")

func readCSV(r io.Reader) ([]csvRow, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	rd := csv.NewReader(bytes.NewReader(data))
	rd.FieldsPerRecord = -1
	rd.TrimLeadingSpace = true
	var hdr []string
	var rows []csvRow
	for {
		rec, err := rd.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, bad("%v", err)
		}
		line, _ := rd.FieldPos(0)
		if hdr == nil {
			for _, h := range rec {
				hdr = append(hdr, strings.ToLower(strings.TrimSpace(h)))
			}
			continue
		}
		if len(rec) == 1 && strings.TrimSpace(rec[0]) == "" {
			continue
		}
		if len(rec) > len(hdr) {
			return nil, bad("line %d: too many columns", line)
		}
		f := map[string]string{}
		for i, v := range rec {
			f[hdr[i]] = strings.TrimSpace(v)
		}
		rows = append(rows, csvRow{line, f})
	}
	if hdr == nil {
		return nil, bad("empty file")
	}
	has := map[string]bool{}
	for _, h := range hdr {
		has[h] = true
	}
	for _, h := range csvHeader {
		if !has[h] {
			return nil, bad("missing column %q (expected %s)", h, strings.Join(csvHeader, ","))
		}
	}
	return rows, nil
}

// importCSV validates the whole file and writes it in a single transaction.
// If any row is invalid nothing is written and Errors is filled.
func importCSV(db *sql.DB, r io.Reader, actor, ip string, defQuota int) (*ImportResult, error) {
	rows, err := readCSV(r)
	if err != nil {
		return nil, err
	}
	res := &ImportResult{}
	err = tx(db, func(t *sql.Tx) error {
		seen := map[string]bool{}
		for _, row := range rows {
			if err := importRow(t, row.f, seen, res, actor, ip, defQuota); err != nil {
				var ue userErr
				if !errors.As(err, &ue) {
					return err
				}
				res.Errors = append(res.Errors, fmt.Sprintf("line %d: %s", row.line, ue))
			}
		}
		if len(res.Errors) > 0 {
			return errInvalidImport
		}
		for _, email := range res.newMailboxes {
			pw := genPassword()
			h, err := hashPassword(pw)
			if err != nil {
				return err
			}
			if _, err := t.Exec(`UPDATE accounts SET password=? WHERE email=?`, h, email); err != nil {
				return err
			}
			res.Creds = append(res.Creds, []string{email, pw})
		}
		audit(t, actor, "csv.import", "", fmt.Sprintf("created=%d updated=%d", res.Created, res.Updated), ip)
		return nil
	})
	if errors.Is(err, errInvalidImport) {
		res.Created, res.Updated, res.Creds = 0, 0, nil
		return res, nil
	}
	if err != nil {
		return nil, err
	}
	return res, nil
}

func importRow(t *sql.Tx, f map[string]string, seen map[string]bool, res *ImportResult, actor, ip string, defQuota int) error {
	email, err := normAddr(f["email"])
	if err != nil {
		return err
	}
	if seen[email] {
		return bad("duplicate %s in file", email)
	}
	seen[email] = true
	dept, err := deptByName(t, f["department"], true)
	if err != nil {
		return err
	}
	switch strings.ToLower(f["type"]) {
	case "mailbox":
		if f["members"] != "" {
			return bad("members only apply to type alias")
		}
		in := AccIn{Email: email, Name: f["name"], Dept: dept, Quota: defQuota, CanSend: true, KeepCopy: true, Role: RoleUser, Forward: f["forward_to"]}
		cur, cerr := loadAccountByEmail(t, email)
		exist := cerr == nil
		if exist {
			in.Quota, in.Role, in.CanSend, in.KeepCopy = cur.Quota, cur.Role, cur.CanSend, cur.KeepCopy
		}
		if f["quota_mb"] != "" {
			q, err := strconv.Atoi(f["quota_mb"])
			if err != nil {
				return bad("invalid quota_mb %q", f["quota_mb"])
			}
			in.Quota = q
		}
		if f["role"] != "" {
			in.Role = strings.ToLower(f["role"])
		}
		if err := in.normalize(t, !exist); err != nil {
			return err
		}
		if exist {
			if err := guardLastSuper(t, cur, in.Role, cur.Active, false); err != nil {
				return bad("%s", err)
			}
			if err := updateAccount(t, cur.ID, in); err != nil {
				return err
			}
			killIfDemoted(t, cur, in.Role)
			audit(t, actor, "account.update", email, "csv", ip)
			res.Updated++
			return nil
		}
		if _, err := insertAccount(t, in, "!"); err != nil {
			return err
		}
		res.newMailboxes = append(res.newMailboxes, email)
		audit(t, actor, "account.create", email, "csv", ip)
		res.Created++
	case "alias":
		if f["role"] != "" || f["forward_to"] != "" || f["quota_mb"] != "" {
			return bad("role, forward_to and quota_mb do not apply to type alias")
		}
		id, aerr := loadAliasByAddress(t, email)
		if aerr != nil {
			if email, err = checkAliasAddress(t, email); err != nil {
				return err
			}
		}
		ms, err := parseMembers(t, email, f["members"])
		if err != nil {
			return err
		}
		if aerr == nil {
			if _, err := t.Exec(`UPDATE aliases SET description=?,department_id=? WHERE id=?`, f["name"], deptOrNil(dept), id); err != nil {
				return err
			}
			if err := setMembers(t, id, ms); err != nil {
				return err
			}
			audit(t, actor, "alias.update", email, "csv", ip)
			res.Updated++
			return nil
		}
		r, err := t.Exec(`INSERT INTO aliases(address,description,department_id) VALUES(?,?,?)`, email, f["name"], deptOrNil(dept))
		if err != nil {
			return err
		}
		id, _ = r.LastInsertId()
		if err := setMembers(t, id, ms); err != nil {
			return err
		}
		audit(t, actor, "alias.create", email, "csv", ip)
		res.Created++
	default:
		return bad("type must be mailbox or alias")
	}
	return nil
}

func killIfDemoted(q querier, cur Account, newRole string) {
	if cur.Role != newRole {
		killSessions(q, cur.ID)
	}
}

func credsCSV(creds [][]string) []byte {
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	w.Write([]string{"email", "password"})
	w.WriteAll(creds)
	return b.Bytes()
}

func exportCSV(db *sql.DB, w io.Writer) error {
	cw := csv.NewWriter(w)
	cw.Write(csvHeader)
	rows, err := db.Query(`SELECT a.email,a.name,COALESCE(d.name,''),a.quota_mb,a.forward_to,a.role
		FROM accounts a LEFT JOIN departments d ON d.id=a.department_id ORDER BY a.email`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var e, n, d, f, r string
		var q int
		if err := rows.Scan(&e, &n, &d, &q, &f, &r); err != nil {
			rows.Close()
			return err
		}
		cw.Write([]string{e, n, "mailbox", d, strconv.Itoa(q), f, "", r})
	}
	rows.Close()
	ar, err := db.Query(`SELECT a.id,a.address,a.description,COALESCE(d.name,'') FROM aliases a LEFT JOIN departments d ON d.id=a.department_id ORDER BY a.address`)
	if err != nil {
		return err
	}
	type al struct {
		id         int64
		addr, desc string
		dept       string
	}
	var als []al
	for ar.Next() {
		var x al
		ar.Scan(&x.id, &x.addr, &x.desc, &x.dept)
		als = append(als, x)
	}
	ar.Close()
	for _, x := range als {
		a, err := loadAlias(db, x.id)
		if err != nil {
			return err
		}
		var ms []string
		for _, m := range a.Members {
			s := m.Dest
			if m.Send {
				s += ":send"
			}
			ms = append(ms, s)
		}
		cw.Write([]string{x.addr, x.desc, "alias", x.dept, "", "", strings.Join(ms, ";"), ""})
	}
	cw.Flush()
	return cw.Error()
}
