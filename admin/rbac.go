package main

import "errors"

// The whole role/permission matrix lives in this file as pure functions.
// Handlers must call these for every action (server-side enforcement).

const (
	RoleSuper    = "superadmin"
	RoleAdmin    = "admin"
	RoleHelpdesk = "helpdesk"
	RoleUser     = "user"
)

// Actor is the logged-in account. Dept 0 means "no department".
type Actor struct {
	ID    int64
	Email string
	Role  string
	Dept  int64
}

// Target is the account being acted upon (or about to be created).
type Target struct {
	Role string
	Dept int64
}

func rank(role string) int {
	switch role {
	case RoleSuper:
		return 4
	case RoleAdmin:
		return 3
	case RoleHelpdesk:
		return 2
	case RoleUser:
		return 1
	}
	return 0
}

func validRole(r string) bool { return rank(r) > 0 }

// sameDept: staff without a department never match anything.
func sameDept(a Actor, dept int64) bool { return a.Dept != 0 && a.Dept == dept }

// outranks implements the rank rule: only a superadmin may touch an account
// of equal or higher rank.
func outranks(a Actor, t Target) bool {
	return a.Role == RoleSuper || rank(a.Role) > rank(t.Role)
}

// Domains, departments, DNS page, audit log, CSV import/export, and changing
// an account's role or department.
func CanGlobalAdmin(a Actor) bool { return a.Role == RoleSuper }

func CanChangeRoleOrDept(a Actor) bool { return a.Role == RoleSuper }

func CanCreateAccount(a Actor, t Target) bool {
	switch a.Role {
	case RoleSuper:
		return validRole(t.Role)
	case RoleAdmin:
		return sameDept(a, t.Dept) && t.Role == RoleUser
	}
	return false
}

func CanEditAccount(a Actor, t Target) bool {
	switch a.Role {
	case RoleSuper:
		return true
	case RoleAdmin:
		return sameDept(a, t.Dept) && t.Role == RoleUser && outranks(a, t)
	}
	return false
}

func CanDeleteAccount(a Actor, t Target) bool { return CanEditAccount(a, t) }

// Create/edit/delete aliases and their members.
func CanManageAlias(a Actor, dept int64) bool {
	switch a.Role {
	case RoleSuper:
		return true
	case RoleAdmin:
		return sameDept(a, dept)
	}
	return false
}

// Listing/viewing accounts and aliases of a department.
func CanList(a Actor, dept int64) bool {
	switch a.Role {
	case RoleSuper:
		return true
	case RoleAdmin, RoleHelpdesk:
		return sameDept(a, dept)
	}
	return false
}

// ListScope tells list queries what the actor may see: everything, one
// department, or nothing.
func ListScope(a Actor) (all bool, dept int64, ok bool) {
	switch a.Role {
	case RoleSuper:
		return true, 0, true
	case RoleAdmin, RoleHelpdesk:
		return false, a.Dept, a.Dept != 0
	}
	return false, 0, false
}

// Password reset and enable/disable share one rule.
func CanResetPassword(a Actor, t Target) bool {
	if !outranks(a, t) {
		return false
	}
	switch a.Role {
	case RoleSuper:
		return true
	case RoleAdmin:
		return sameDept(a, t.Dept) && (t.Role == RoleUser || t.Role == RoleHelpdesk)
	case RoleHelpdesk:
		return sameDept(a, t.Dept) && t.Role == RoleUser
	}
	return false
}

func CanSetActive(a Actor, t Target) bool { return CanResetPassword(a, t) }

func CanChangeOwnPassword(Actor) bool { return true }

func CanChangeOwnForward(_ Actor, allowUserForward bool) bool { return allowUserForward }

var ErrLastSuperadmin = errors.New("cannot delete, disable or demote the last active superadmin")

// GuardLastSuperadmin: target is the account before the change; activeSupers
// is the number of active superadmins (including target if it is one).
func GuardLastSuperadmin(targetRole string, targetActive bool, activeSupers int, newRole string, newActive, deleting bool) error {
	if targetRole == RoleSuper && targetActive && activeSupers <= 1 &&
		(deleting || newRole != RoleSuper || !newActive) {
		return ErrLastSuperadmin
	}
	return nil
}
