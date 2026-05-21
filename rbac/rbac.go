package rbac

// Checker kiểm tra quyền của subject
type Checker interface {
	Can(subject, obj, act string) (bool, error)
}

// Manager quản lý roles và permissions
type Manager interface {
	GrantRole(subject, role string) error
	RevokeRole(subject, role string) error
	DeleteRoles(subject string) error

	GrantPermission(role, obj, act string) error
	GrantPermissions(rules [][]string) error
	RevokePermission(role, obj, act string) error
}
