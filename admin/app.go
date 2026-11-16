package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"html/template"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed templates/*.html
var tplFS embed.FS

//go:embed static/*
var staticFS embed.FS

type Config struct {
	DBPath, DKIMDir, Listen, MailHost, PrimaryDomain string
	AdminEmail, AdminPassword                        string
	SessionHours, DefaultQuota                       int
	AllowUserForward, InsecureCookies                bool
}

type App struct {
	db        *sql.DB
	cfg       Config
	tpl       map[string]*template.Template
	throttle  *throttle
	dummyHash string
}

func newApp(db *sql.DB, cfg Config) (*App, error) {
	a := &App{db: db, cfg: cfg, tpl: map[string]*template.Template{}, throttle: &throttle{m: map[string][]time.Time{}}}
	pages, err := fs.Glob(tplFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	for _, p := range pages {
		name := strings.TrimSuffix(strings.TrimPrefix(p, "templates/"), ".html")
		if name == "layout" {
			continue
		}
		t, err := template.ParseFS(tplFS, "templates/layout.html", p)
		if err != nil {
			return nil, err
		}
		a.tpl[name] = t
	}
	a.dummyHash, err = hashPassword("dummy-password-for-constant-work")
	return a, err
}

// ---- login throttle: 5 failures per 15 min per (ip, email) ----

type throttle struct {
	mu sync.Mutex
	m  map[string][]time.Time
}

const (
	throttleMax    = 5
	throttleWindow = 15 * time.Minute
)

func (t *throttle) recent(key string) []time.Time {
	cut := time.Now().Add(-throttleWindow)
	var keep []time.Time
	for _, x := range t.m[key] {
		if x.After(cut) {
			keep = append(keep, x)
		}
	}
	if len(keep) == 0 {
		delete(t.m, key)
	} else {
		t.m[key] = keep
	}
	return keep
}

func (t *throttle) blocked(key string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.recent(key)) >= throttleMax
}

func (t *throttle) fail(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.m) > 10000 {
		for k := range t.m {
			t.recent(k)
		}
	}
	t.m[key] = append(t.recent(key), time.Now())
}

func (t *throttle) reset(key string) {
	t.mu.Lock()
	delete(t.m, key)
	t.mu.Unlock()
}

// ---- request context ----

type Ctx struct {
	A    *App
	W    http.ResponseWriter
	R    *http.Request
	U    Actor
	CSRF string
	IP   string
}

// clientIP trusts X-Forwarded-For only when the peer is a private/loopback
// address (the reverse proxy); it takes the right-most entry, which the proxy added.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip, err := netip.ParseAddr(host); err == nil && (ip.IsLoopback() || ip.IsPrivate()) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if v := strings.TrimSpace(parts[len(parts)-1]); v != "" {
				return v
			}
		}
	}
	return host
}

func sha(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func randToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

const sessionCookie = "rm_session"

func (a *App) setCookie(w http.ResponseWriter, name, val string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: val, Path: "/", MaxAge: maxAge, HttpOnly: true,
		Secure: !a.cfg.InsecureCookies, SameSite: http.SameSiteStrictMode})
}

func (a *App) secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		if !strings.HasPrefix(r.URL.Path, "/static/") {
			h.Set("Cache-Control", "no-store")
		}
		if !a.cfg.InsecureCookies {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

// auth wraps a handler: valid session required, CSRF checked on POST.
func (a *App) auth(h func(*Ctx)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := &Ctx{A: a, W: w, R: r, IP: clientIP(r)}
		ck, err := r.Cookie(sessionCookie)
		if err != nil {
			c.loginRedirect()
			return
		}
		err = a.db.QueryRow(`SELECT s.csrf,a.id,a.email,a.role,COALESCE(a.department_id,0)
			FROM sessions s JOIN accounts a ON a.id=s.account_id
			WHERE s.token_hash=? AND s.expires_at>datetime('now') AND a.active=1`, sha(ck.Value)).
			Scan(&c.CSRF, &c.U.ID, &c.U.Email, &c.U.Role, &c.U.Dept)
		if err != nil {
			a.setCookie(w, sessionCookie, "", -1)
			c.loginRedirect()
			return
		}
		if r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(w, r.Body, 8<<20)
			if !tokenEq(r.PostFormValue("csrf"), c.CSRF) {
				c.status(http.StatusForbidden, "Invalid or missing CSRF token.")
				return
			}
		}
		h(c)
	}
}

func tokenEq(a, b string) bool {
	return a != "" && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func (c *Ctx) loginRedirect() { http.Redirect(c.W, c.R, "/login", http.StatusSeeOther) }

// ---- responses ----

func (c *Ctx) render(name string, data map[string]any) { c.renderStatus(http.StatusOK, name, data) }

func (c *Ctx) renderStatus(code int, name string, data map[string]any) {
	if data == nil {
		data = map[string]any{}
	}
	if c.U.ID != 0 {
		u := c.U
		data["U"] = &u
		data["CSRF"] = c.CSRF
		data["Super"] = CanGlobalAdmin(u)
		all, _, ok := ListScope(u)
		data["CanList"] = all || ok
	}
	if _, ok := data["Msg"]; !ok {
		m := c.R.URL.Query().Get("msg")
		if len(m) > 200 {
			m = m[:200]
		}
		data["Msg"] = m
	}
	var buf bytes.Buffer
	if err := c.A.tpl[name].ExecuteTemplate(&buf, "layout", data); err != nil {
		log.Printf("render %s: %v", name, err)
		http.Error(c.W, "internal error", 500)
		return
	}
	c.W.Header().Set("Content-Type", "text/html; charset=utf-8")
	c.W.WriteHeader(code)
	c.W.Write(buf.Bytes())
}

func (c *Ctx) status(code int, msg string) {
	c.renderStatus(code, "error", map[string]any{"Title": strconv.Itoa(code), "Code": code, "Text": msg})
}

func (c *Ctx) forbidden() { c.status(http.StatusForbidden, "You are not allowed to do that.") }
func (c *Ctx) notFound()  { c.status(http.StatusNotFound, "Not found.") }

// fail reports an error: user-facing ones are shown, others logged as 500.
func (c *Ctx) fail(err error) {
	if err == errNotFound {
		c.notFound()
		return
	}
	if ue, ok := err.(userErr); ok {
		c.status(http.StatusBadRequest, string(ue))
		return
	}
	log.Printf("%s %s: %v", c.R.Method, c.R.URL.Path, err)
	c.status(http.StatusInternalServerError, "Internal error.")
}

func (c *Ctx) redirect(path, msg string) {
	if msg != "" {
		sep := "?"
		if strings.Contains(path, "?") {
			sep = "&"
		}
		path += sep + "msg=" + url.QueryEscape(msg)
	}
	http.Redirect(c.W, c.R, path, http.StatusSeeOther)
}

func (c *Ctx) audit(q querier, action, target, detail string) {
	audit(q, c.U.Email, action, target, detail, c.IP)
}

func (c *Ctx) id() (int64, bool) {
	id, err := strconv.ParseInt(c.R.PathValue("id"), 10, 64)
	return id, err == nil
}

func (c *Ctx) form(k string) string  { return strings.TrimSpace(c.R.PostFormValue(k)) }
func (c *Ctx) checked(k string) bool { return c.R.PostFormValue(k) != "" }
func (c *Ctx) formInt(k string, def int) int {
	v, err := strconv.Atoi(c.form(k))
	if err != nil {
		return def
	}
	return v
}
func (c *Ctx) formID(k string) int64 { return int64(c.formInt(k, 0)) }

// ---- routes ----

func (a *App) routes() http.Handler {
	mux := http.NewServeMux()
	sub, _ := fs.Sub(staticFS, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(sub)))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := a.db.Ping(); err != nil {
			http.Error(w, "db error", 503)
			return
		}
		w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /login", a.loginPage)
	mux.HandleFunc("POST /login", a.loginPost)
	mux.HandleFunc("POST /logout", a.auth((*Ctx).logout))

	g := func(p string, h func(*Ctx)) {
		mux.HandleFunc(p, a.auth(h))
	}
	g("GET /{$}", (*Ctx).dashboard)
	g("GET /accounts", (*Ctx).accountList)
	g("GET /accounts/new", (*Ctx).accountNew)
	g("POST /accounts/new", (*Ctx).accountCreate)
	g("GET /accounts/{id}", (*Ctx).accountView)
	g("POST /accounts/{id}", (*Ctx).accountUpdate)
	g("POST /accounts/{id}/password", (*Ctx).accountPassword)
	g("POST /accounts/{id}/active", (*Ctx).accountActive)
	g("POST /accounts/{id}/delete", (*Ctx).accountDelete)
	g("GET /aliases", (*Ctx).aliasList)
	g("GET /aliases/new", (*Ctx).aliasNew)
	g("POST /aliases/new", (*Ctx).aliasCreate)
	g("GET /aliases/{id}", (*Ctx).aliasView)
	g("POST /aliases/{id}", (*Ctx).aliasUpdate)
	g("POST /aliases/{id}/delete", (*Ctx).aliasDelete)
	g("GET /departments", (*Ctx).deptList)
	g("POST /departments", (*Ctx).deptCreate)
	g("POST /departments/{id}", (*Ctx).deptRename)
	g("POST /departments/{id}/delete", (*Ctx).deptDelete)
	g("GET /domains", (*Ctx).domainList)
	g("POST /domains", (*Ctx).domainCreate)
	g("POST /domains/{name}/delete", (*Ctx).domainDelete)
	g("GET /dns", (*Ctx).dnsPage)
	g("GET /audit", (*Ctx).auditPage)
	g("GET /import", (*Ctx).importPage)
	g("POST /import", (*Ctx).importPost)
	g("GET /export.csv", (*Ctx).exportGet)
	g("GET /me", (*Ctx).mePage)
	g("POST /me/password", (*Ctx).mePassword)
	g("POST /me/forward", (*Ctx).meForward)
	return a.secure(mux)
}
