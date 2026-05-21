package rbac

import (
	"fmt"

	"github.com/casbin/casbin/v3"
	"github.com/casbin/casbin/v3/model"
	"github.com/jackc/pgx/v5/pgxpool"
	pgxadapter "github.com/noho-digital/casbin-pgx-adapter"
)

func NewCasbinEnforcer(pool *pgxpool.Pool, opts ...Option) (casbin.IEnforcer, error) {
	o := defaultOptions()
	for _, opt := range opts {
		opt(o)
	}

	var adapterOpts []pgxadapter.Option
	for _, idx := range o.Indexes {
		adapterOpts = append(adapterOpts, pgxadapter.WithIndex(idx.columns...))
	}

	adapter, err := pgxadapter.NewAdapterWithPool(pool, adapterOpts...)
	if err != nil {
		return nil, fmt.Errorf("rbac: failed to create adapter: %w", err)
	}

	var e *casbin.SyncedCachedEnforcer
	if o.ModelText != "" {
		m, err := model.NewModelFromString(o.ModelText)
		if err != nil {
			return nil, fmt.Errorf("rbac: failed to parse model: %w", err)
		}
		e, err = casbin.NewSyncedCachedEnforcer(m, adapter)
	} else {
		e, err = casbin.NewSyncedCachedEnforcer(o.ModelPath, adapter)
	}
	if err != nil {
		return nil, fmt.Errorf("rbac: failed to create enforcer: %w", err)
	}

	if err = e.LoadPolicy(); err != nil {
		return nil, fmt.Errorf("rbac: failed to load policy: %w", err)
	}

	e.EnableAutoSave(true)
	return e, nil
}
