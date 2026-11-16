package main

import (
	"bytes"
	"database/sql"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
)

const testPW = "correct-horse-1"

var (
	hashOnce sync.Once
	testHash string
)

type testEnv struct {
	t   *testing.T
	db  *sql.DB
	app *App
	srv *httptest.Server
}

func newEnv(t *testing.T) *testEnv {
	t.Helper()
	dir := t.TempDir()
	cfg := Config{DBPath: filepath.Join(dir, "db", "mail.db"), DKIMDir: filepath.Join(dir, "dkim"), Listen: ":0",
		MailHost: "mail.example.com", PrimaryDomain: "example.com", SessionHours: 1, DefaultQuota: 1024, InsecureCookies: true}
	db, err := openDB(cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := bootstrap(db, cfg); err != nil {
		t.Fatal(err)
	}
	app, err := newApp(db, cfg)
	if err != nil {
		t.Fatal(err)
	}
	e := &testEnv{t, db, app, httptest.NewServer(app.routes())}
	t.Cleanup(func() { e.srv.Close(); db.Close() })
	return e
}

// addAccount inserts directly (fast); password is always testPW.
func (e *testEnv) addAccount(email, role string, dept int64) int64 {
	e.t.Helper()
	hashOnce.Do(func() { testHash, _ = hashPassword(testPW) })
	id, err := insertAccount(e.db, AccIn{Email: email, Role: role, Dept: dept, Quota: 1024, CanSend: true, KeepCopy: true}, testHash)
	if err != nil {
		e.t.Fatal(err)
	}
	return id
}

func (e *testEnv) addDept(name string) int64 {
	e.t.Helper()
	id, err := deptByName(e.db, name, true)
	if err != nil {
		e.t.Fatal(err)
	}
	return id
}

func (e *testEnv) accountID(email string) int64 {
	var id int64
	if err := e.db.QueryRow(`SELECT id FROM accounts WHERE email=?`, email).Scan(&id); err != nil {
		e.t.Fatalf("account %s: %v", email, err)
	}
	return id
}

func (e *testEnv) count(query string, args ...any) int {
	var n int
	e.db.QueryRow(query, args...).Scan(&n)
	return n
}

type client struct {
	t    *testing.T
	c    *http.Client
	base string
	csrf string
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func (e *testEnv) newClient() *client {
	jar, _ := cookiejar.New(nil)
	return &client{t: e.t, base: e.srv.URL, c: &http.Client{Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

// login performs the real login flow and returns a logged-in client.
func (e *testEnv) login(email string) *client { return e.loginPW(email, testPW) }

func (e *testEnv) loginPW(email, pw string) *client {
	e.t.Helper()
	c := e.newClient()
	code, _, loc := c.login(email, pw)
	if code != 303 || loc != "/" {
		e.t.Fatalf("login %s: %d %s", email, code, loc)
	}
	_, body, _ := c.get("/me")
	m := csrfRe.FindStringSubmatch(body)
	if m == nil {
		e.t.Fatal("no csrf on /me")
	}
	c.csrf = m[1]
	return c
}

func (c *client) login(email, pw string) (int, string, string) {
	_, body, _ := c.get("/login")
	m := csrfRe.FindStringSubmatch(body)
	if m == nil {
		c.t.Fatal("no login csrf")
	}
	return c.postRaw("/login", url.Values{"csrf": {m[1]}, "email": {email}, "password": {pw}})
}

func (c *client) do(req *http.Request) (int, string, string) {
	resp, err := c.c.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header.Get("Location")
}

func (c *client) get(path string) (int, string, string) {
	req, _ := http.NewRequest("GET", c.base+path, nil)
	return c.do(req)
}

func (c *client) postRaw(path string, v url.Values) (int, string, string) {
	req, _ := http.NewRequest("POST", c.base+path, strings.NewReader(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return c.do(req)
}

// post adds the session's CSRF token.
func (c *client) post(path string, v url.Values) (int, string, string) {
	if v == nil {
		v = url.Values{}
	}
	v.Set("csrf", c.csrf)
	return c.postRaw(path, v)
}

func multipartFile(field, name, content, csrf string) (*bytes.Buffer, string) {
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	w.WriteField("csrf", csrf)
	fw, _ := w.CreateFormFile(field, name)
	fw.Write([]byte(content))
	w.Close()
	return &b, w.FormDataContentType()
}

func newReq(c *client, path string, body io.Reader, ctype string) *http.Request {
	req, _ := http.NewRequest("POST", c.base+path, body)
	req.Header.Set("Content-Type", ctype)
	return req
}
