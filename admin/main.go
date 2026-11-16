// rokmail: admin panel and CLI for the rokmail self-hosted mail stack.
package main

import (
	"database/sql"
	_ "embed"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

//go:embed schema.sql
var schemaSQL string

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envBool(k string) bool {
	switch strings.ToLower(os.Getenv(k)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func envInt(k string, def int) int {
	if n, err := strconv.Atoi(os.Getenv(k)); err == nil && n > 0 {
		return n
	}
	return def
}

func loadConfig() Config {
	return Config{
		DBPath:           env("DB_PATH", "/db/mail.db"),
		DKIMDir:          env("DKIM_DIR", "/dkim"),
		Listen:           env("LISTEN", ":8080"),
		MailHost:         strings.ToLower(os.Getenv("MAIL_HOST")),
		PrimaryDomain:    strings.ToLower(os.Getenv("PRIMARY_DOMAIN")),
		AdminEmail:       os.Getenv("ADMIN_EMAIL"),
		AdminPassword:    os.Getenv("ADMIN_PASSWORD"),
		SessionHours:     envInt("SESSION_HOURS", 12),
		DefaultQuota:     envInt("DEFAULT_QUOTA_MB", 1024),
		AllowUserForward: envBool("ALLOW_USER_FORWARD"),
		InsecureCookies:  envBool("INSECURE_COOKIES"),
	}
}

func main() {
	syscall.Umask(0) // db + dkim files must be readable by other containers
	cmd, args := "serve", os.Args[1:]
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	cfg := loadConfig()
	var err error
	switch cmd {
	case "serve":
		err = serve(cfg)
	case "admin-create":
		err = cmdAdminCreate(cfg, args)
	case "passwd":
		err = cmdPasswd(cfg, args)
	case "import":
		err = cmdImport(cfg, args)
	case "backup-db":
		err = cmdBackup(cfg, args)
	default:
		fmt.Fprintln(os.Stderr, "usage: rokmail [serve | admin-create -email E -password P | passwd -email E [-password P] | import FILE.csv | backup-db DEST]")
		os.Exit(2)
	}
	if err != nil {
		log.Fatalf("rokmail %s: %v", cmd, err)
	}
}

func serve(cfg Config) error {
	db, err := openDB(cfg.DBPath)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := bootstrap(db, cfg); err != nil {
		return fmt.Errorf("bootstrap: %w", err)
	}
	if err := ensureAllDKIM(db, cfg.DKIMDir); err != nil {
		return err
	}
	app, err := newApp(db, cfg)
	if err != nil {
		return err
	}
	srv := &http.Server{Addr: cfg.Listen, Handler: app.routes(),
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 60 * time.Second,
		WriteTimeout: 5 * time.Minute, IdleTimeout: 2 * time.Minute}
	log.Printf("rokmail admin listening on %s", cfg.Listen)
	return srv.ListenAndServe()
}

func cmdAdminCreate(cfg Config, args []string) error {
	fs := flag.NewFlagSet("admin-create", flag.ExitOnError)
	email := fs.String("email", "", "superadmin email")
	pw := fs.String("password", "", "password (min 10 chars)")
	fs.Parse(args)
	db, err := openDB(cfg.DBPath)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := bootstrap(db, Config{PrimaryDomain: cfg.PrimaryDomain}); err != nil {
		return err
	}
	e, err := normAddr(*email)
	if err != nil {
		return err
	}
	if err := checkPassword(*pw); err != nil {
		return err
	}
	return tx(db, func(t *sql.Tx) error {
		if err := ensureDomain(t, domainOf(e)); err != nil {
			return err
		}
		if _, err := upsertSuperadmin(t, e, *pw, cfg.DefaultQuota); err != nil {
			return err
		}
		audit(t, "cli", "account.admin-create", e, "", "")
		return nil
	})
}

func cmdPasswd(cfg Config, args []string) error {
	fs := flag.NewFlagSet("passwd", flag.ExitOnError)
	email := fs.String("email", "", "account email")
	pw := fs.String("password", "", "new password (default: generate and print)")
	fs.Parse(args)
	db, err := openDB(cfg.DBPath)
	if err != nil {
		return err
	}
	defer db.Close()
	e, err := normAddr(*email)
	if err != nil {
		return err
	}
	gen := *pw == ""
	if gen {
		*pw = genPassword()
	}
	if err := checkPassword(*pw); err != nil {
		return err
	}
	h, err := hashPassword(*pw)
	if err != nil {
		return err
	}
	err = tx(db, func(t *sql.Tx) error {
		a, err := loadAccountByEmail(t, e)
		if err != nil {
			return bad("no such account %s", e)
		}
		if _, err := t.Exec(`UPDATE accounts SET password=?,updated_at=datetime('now') WHERE id=?`, h, a.ID); err != nil {
			return err
		}
		killSessions(t, a.ID)
		audit(t, "cli", "account.password", e, "", "")
		return nil
	})
	if err == nil && gen {
		fmt.Printf("%s %s\n", e, *pw)
	}
	return err
}

func cmdImport(cfg Config, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: rokmail import FILE.csv")
	}
	f, err := os.Open(args[0])
	if err != nil {
		return err
	}
	defer f.Close()
	db, err := openDB(cfg.DBPath)
	if err != nil {
		return err
	}
	defer db.Close()
	res, err := importCSV(db, f, "cli", "", cfg.DefaultQuota)
	if err != nil {
		return err
	}
	if len(res.Errors) > 0 {
		for _, e := range res.Errors {
			fmt.Fprintln(os.Stderr, e)
		}
		return fmt.Errorf("nothing imported: %d invalid line(s)", len(res.Errors))
	}
	fmt.Fprintf(os.Stderr, "imported: %d created, %d updated\n", res.Created, res.Updated)
	if len(res.Creds) > 0 {
		os.Stdout.Write(credsCSV(res.Creds))
	}
	return nil
}

func cmdBackup(cfg Config, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: rokmail backup-db DEST")
	}
	db, err := openDB(cfg.DBPath)
	if err != nil {
		return err
	}
	defer db.Close()
	if _, err := db.Exec(`VACUUM INTO ?`, args[0]); err != nil {
		return err
	}
	return os.Chmod(args[0], 0o600)
}
