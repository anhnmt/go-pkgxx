package rbac

type index struct {
	columns []string
}

type EnforcerOptions struct {
	TableName string
	ModelPath string
	ModelText string
	Indexes   []index
}

type Option func(*EnforcerOptions)

func WithTableName(name string) Option {
	return func(o *EnforcerOptions) {
		o.TableName = name
	}
}

func WithModelPath(path string) Option {
	return func(o *EnforcerOptions) {
		o.ModelPath = path
	}
}

func WithModelText(text string) Option {
	return func(o *EnforcerOptions) {
		o.ModelText = text
	}
}

func WithIndex(columns ...string) Option {
	return func(o *EnforcerOptions) {
		o.Indexes = append(o.Indexes, index{columns: columns})
	}
}

func defaultOptions() *EnforcerOptions {
	return &EnforcerOptions{
		TableName: "casbin_rules",
	}
}
