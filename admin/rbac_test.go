package main

import (
	"fmt"
	"testing"
)

var roles = []string{RoleSuper, RoleAdmin, RoleHelpdesk, RoleUser}

// For every capability that depends on the target account, the explicit list of
// allowed "actor/target/dept" combinations (dept: own|other). Everything else must be denied.
func TestRBACTargetMatrix(t *testing.T) {
	caps := []struct {
		name  string
		fn    func(Actor, Target) bool
		allow map[string]bool
	}{
		{"create", CanCreateAccount, set("superadmin/superadmin/own", "superadmin/superadmin/other", "superadmin/admin/own", "superadmin/admin/other",
			"superadmin/helpdesk/own", "superadmin/helpdesk/other", "superadmin/user/own", "superadmin/user/other",
			"admin/user/own")},
		{"edit", CanEditAccount, set("superadmin/superadmin/own", "superadmin/superadmin/other", "superadmin/admin/own", "superadmin/admin/other",
			"superadmin/helpdesk/own", "superadmin/helpdesk/other", "superadmin/user/own", "superadmin/user/other",
			"admin/user/own")},
		{"delete", CanDeleteAccount, set("superadmin/superadmin/own", "superadmin/superadmin/other", "superadmin/admin/own", "superadmin/admin/other",
			"superadmin/helpdesk/own", "superadmin/helpdesk/other", "superadmin/user/own", "superadmin/user/other",
			"admin/user/own")},
		{"reset", CanResetPassword, set("superadmin/superadmin/own", "superadmin/superadmin/other", "superadmin/admin/own", "superadmin/admin/other",
			"superadmin/helpdesk/own", "superadmin/helpdesk/other", "superadmin/user/own", "superadmin/user/other",
			"admin/user/own", "admin/helpdesk/own",
			"helpdesk/user/own")},
		{"setactive", CanSetActive, set("superadmin/superadmin/own", "superadmin/superadmin/other", "superadmin/admin/own", "superadmin/admin/other",
			"superadmin/helpdesk/own", "superadmin/helpdesk/other", "superadmin/user/own", "superadmin/user/other",
			"admin/user/own", "admin/helpdesk/own",
			"helpdesk/user/own")},
	}
	for _, c := range caps {
		for _, ar := range roles {
			for _, tr := range roles {
				for _, rel := range []string{"own", "other"} {
					actor := Actor{Role: ar, Dept: 1}
					tgt := Target{Role: tr, Dept: 1}
					if rel == "other" {
						tgt.Dept = 2
					}
					key := fmt.Sprintf("%s/%s/%s", ar, tr, rel)
					if got, want := c.fn(actor, tgt), c.allow[key]; got != want {
						t.Errorf("%s %s: got %v want %v", c.name, key, got, want)
					}
				}
			}
		}
	}
}

func set(keys ...string) map[string]bool {
	m := map[string]bool{}
	for _, k := range keys {
		m[k] = true
	}
	return m
}

func TestRBACNoDepartment(t *testing.T) {
	// staff without a department see and manage nothing, even department-less objects
	for _, r := range []string{RoleAdmin, RoleHelpdesk} {
		a := Actor{Role: r, Dept: 0}
		tgt := Target{Role: RoleUser, Dept: 0}
		if CanList(a, 0) || CanManageAlias(a, 0) || CanCreateAccount(a, tgt) || CanEditAccount(a, tgt) ||
			CanDeleteAccount(a, tgt) || CanResetPassword(a, tgt) || CanSetActive(a, tgt) {
			t.Errorf("%s without department must have no access", r)
		}
		if _, _, ok := ListScope(a); ok {
			t.Errorf("%s without department: ListScope must be empty", r)
		}
	}
}

func TestRBACListAliasGlobal(t *testing.T) {
	for _, ar := range roles {
		for _, own := range []bool{true, false} {
			dept := int64(2)
			if own {
				dept = 1
			}
			a := Actor{Role: ar, Dept: 1}
			wantList := ar == RoleSuper || ((ar == RoleAdmin || ar == RoleHelpdesk) && own)
			wantAlias := ar == RoleSuper || (ar == RoleAdmin && own)
			if got := CanList(a, dept); got != wantList {
				t.Errorf("CanList %s own=%v: got %v", ar, own, got)
			}
			if got := CanManageAlias(a, dept); got != wantAlias {
				t.Errorf("CanManageAlias %s own=%v: got %v", ar, own, got)
			}
		}
		a := Actor{Role: ar, Dept: 1}
		isSuper := ar == RoleSuper
		if CanGlobalAdmin(a) != isSuper || CanChangeRoleOrDept(a) != isSuper {
			t.Errorf("global admin caps for %s", ar)
		}
		if !CanChangeOwnPassword(a) {
			t.Errorf("%s must change own password", ar)
		}
		if CanChangeOwnForward(a, false) || !CanChangeOwnForward(a, true) {
			t.Errorf("own forward flag for %s", ar)
		}
		all, dept, ok := ListScope(a)
		switch ar {
		case RoleSuper:
			if !all || !ok {
				t.Error("super scope")
			}
		case RoleAdmin, RoleHelpdesk:
			if all || dept != 1 || !ok {
				t.Errorf("%s scope", ar)
			}
		default:
			if all || ok {
				t.Error("user scope must be empty")
			}
		}
	}
}

func TestRankRule(t *testing.T) {
	// nobody but superadmin can modify an equal or higher rank
	for _, ar := range []string{RoleAdmin, RoleHelpdesk, RoleUser} {
		for _, tr := range roles {
			if rank(tr) >= rank(ar) {
				a, tgt := Actor{Role: ar, Dept: 1}, Target{Role: tr, Dept: 1}
				if CanEditAccount(a, tgt) || CanResetPassword(a, tgt) || CanSetActive(a, tgt) || CanDeleteAccount(a, tgt) {
					t.Errorf("%s must not modify %s", ar, tr)
				}
			}
		}
	}
	if !CanEditAccount(Actor{Role: RoleSuper}, Target{Role: RoleSuper}) {
		t.Error("superadmin may modify superadmin")
	}
}

func TestGuardLastSuperadmin(t *testing.T) {
	tests := []struct {
		name         string
		role         string
		active       bool
		supers       int
		newRole      string
		newActive    bool
		deleting     bool
		wantRejected bool
	}{
		{"delete last", RoleSuper, true, 1, RoleSuper, true, true, true},
		{"disable last", RoleSuper, true, 1, RoleSuper, false, false, true},
		{"demote last", RoleSuper, true, 1, RoleAdmin, true, false, true},
		{"delete one of two", RoleSuper, true, 2, RoleSuper, true, true, false},
		{"disable one of two", RoleSuper, true, 2, RoleSuper, false, false, false},
		{"demote one of two", RoleSuper, true, 2, RoleUser, true, false, false},
		{"no-op edit of last", RoleSuper, true, 1, RoleSuper, true, false, false},
		{"delete non-super", RoleAdmin, true, 1, RoleAdmin, true, true, false},
		{"delete inactive super", RoleSuper, false, 1, RoleSuper, false, true, false},
	}
	for _, tc := range tests {
		err := GuardLastSuperadmin(tc.role, tc.active, tc.supers, tc.newRole, tc.newActive, tc.deleting)
		if (err != nil) != tc.wantRejected {
			t.Errorf("%s: err=%v wantRejected=%v", tc.name, err, tc.wantRejected)
		}
	}
}
