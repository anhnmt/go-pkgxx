package rbac

import (
	"github.com/casbin/casbin/v3"
)

var _ Checker = (*CasbinAuthz)(nil)
var _ Manager = (*CasbinAuthz)(nil)

type CasbinAuthz struct {
	enforcer casbin.IEnforcer
}

func New(enforcer casbin.IEnforcer) *CasbinAuthz {
	return &CasbinAuthz{enforcer: enforcer}
}

func (c *CasbinAuthz) Can(subject, obj, act string) (bool, error) {
	return c.enforcer.Enforce(subject, obj, act)
}

func (c *CasbinAuthz) GrantRole(subject, role string) error {
	_, err := c.enforcer.AddGroupingPolicy(subject, role)
	return err
}

func (c *CasbinAuthz) RevokeRole(subject, role string) error {
	_, err := c.enforcer.RemoveGroupingPolicy(subject, role)
	return err
}

func (c *CasbinAuthz) DeleteRoles(subject string) error {
	_, err := c.enforcer.DeleteRolesForUser(subject)
	return err
}

func (c *CasbinAuthz) GrantPermission(role, obj, act string) error {
	_, err := c.enforcer.AddPolicy(role, obj, act)
	return err
}

func (c *CasbinAuthz) GrantPermissions(rules [][]string) error {
	_, err := c.enforcer.AddPolicies(rules)
	return err
}

func (c *CasbinAuthz) RevokePermission(role, obj, act string) error {
	_, err := c.enforcer.RemovePolicy(role, obj, act)
	return err
}
