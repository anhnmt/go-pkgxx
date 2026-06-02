package logger

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gopkg.in/natefinch/lumberjack.v2"
)

type Logger struct {
	Level  string `json:"level,omitempty"`  // trace | debug | info | warn | error | fatal | panic
	Pretty bool   `json:"pretty,omitempty"` // human-readable console output (dev mode)
	// File output & rotation
	LogFile    string `json:"log_file,omitempty"`     // path to log file; empty = stdout only
	MaxSizeMb  int32  `json:"max_size_mb,omitempty"`  // MB before rotation
	MaxBackups int32  `json:"max_backups,omitempty"`  // rotated files to keep
	MaxAgeDays int32  `json:"max_age_days,omitempty"` // max age of rotated files (days)
}

// Init applies cfg to zerolog's global variables and overwrites log.Logger.
// Call once at application startup.
func Init(cfg *Logger) {
	level, err := zerolog.ParseLevel(cfg.Level)
	if err != nil {
		level = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(level)

	// Pin timestamp source to UTC
	zerolog.TimestampFunc = func() time.Time { return time.Now().UTC() }

	zerolog.CallerMarshalFunc = func(pc uintptr, file string, line int) string {
		// Shorten to last two path components for brevity.
		short := file
		count := 0
		for i := len(file) - 1; i > 0; i-- {
			if file[i] == '/' {
				count++
				if count == 2 {
					short = file[i+1:]
					break
				}
			}
		}
		return short + ":" + strconv.Itoa(line)
	}

	zerolog.ErrorStackMarshaler = func(err error) interface{} {
		if err == nil {
			return nil
		}
		buf := make([]byte, 4096)
		n := runtime.Stack(buf, false)
		return string(buf[:n])
	}

	zerolog.ErrorHandler = func(e error) {
		// Write to stderr without using the logger itself to avoid recursion.
		_, _ = os.Stderr.WriteString("[zerolog] write error: " + e.Error() + "\n")
	}

	var writers []io.Writer

	if cfg.Pretty {
		writers = append(writers, zerolog.ConsoleWriter{
			Out:        os.Stdout,
			TimeFormat: time.RFC3339,
		})
	} else {
		writers = append(writers, os.Stdout)
	}

	if cfg.LogFile != "" {
		if mkErr := os.MkdirAll(filepath.Dir(cfg.LogFile), 0o755); mkErr == nil {
			writers = append(writers, &lumberjack.Logger{
				Filename:   cfg.LogFile,
				MaxSize:    int(cfg.MaxSizeMb),
				MaxBackups: int(cfg.MaxBackups),
				MaxAge:     int(cfg.MaxAgeDays),
				Compress:   true,
			})
		}
	}

	var out io.Writer
	if len(writers) == 1 {
		out = writers[0]
	} else {
		out = zerolog.MultiLevelWriter(writers...)
	}

	ctx := zerolog.New(out).With().Timestamp()
	log.Logger = ctx.Logger()
}

// ── Convenience wrappers ──────────────────────────────────────────────────────
// These delegate to log.Logger so they respect all globals set in Init().

// Debug logs at debug level with optional key/value pairs.
//
//	logger.Debug("cache miss", "key", key)
func Debug(msg string, fields ...any) {
	appendFields(log.Debug(), fields).Msg(msg)
}

// Info logs at info level.
func Info(msg string, fields ...any) {
	appendFields(log.Info(), fields).Msg(msg)
}

// Warn logs at warn level.
func Warn(msg string, fields ...any) {
	appendFields(log.Warn(), fields).Msg(msg)
}

// Error logs at error level. err is attached under zerolog.ErrorFieldName.
func Error(msg string, err error, fields ...any) {
	appendFields(log.Error().Err(err), fields).Msg(msg)
}

// Fatal logs at fatal level then calls zerolog.FatalExitFunc (default os.Exit(1)).
func Fatal(msg string, err error, fields ...any) {
	appendFields(log.Fatal().Err(err), fields).Msg(msg)
}

// Panic logs at panic level then panics.
func Panic(msg string, err error, fields ...any) {
	appendFields(log.Panic().Err(err), fields).Msg(msg)
}

// ── Scoped loggers ────────────────────────────────────────────────────────────

// WithField returns a child of log.Logger pre-set with one key/value.
func WithField(key string, value any) zerolog.Logger {
	return log.With().Interface(key, value).Logger()
}

// WithFields returns a child of log.Logger pre-set with multiple key/values.
func WithFields(fields map[string]any) zerolog.Logger {
	ctx := log.With()
	for k, v := range fields {
		ctx = ctx.Interface(k, v)
	}
	return ctx.Logger()
}

// WithComponent is a common pattern for component-scoped loggers.
func WithComponent(name string) zerolog.Logger {
	return log.With().Str("component", name).Logger()
}

// ── Runtime controls ──────────────────────────────────────────────────────────

// SetLevel changes the global log level at runtime without restarting.
func SetLevel(level string) {
	l, err := zerolog.ParseLevel(level)
	if err != nil {
		l = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(l)
}

// GetLevel returns the current global log level string.
func GetLevel() string {
	return zerolog.GlobalLevel().String()
}

// ── Internal helpers ──────────────────────────────────────────────────────────

// appendFields adds variadic key/value pairs to an event.
// Pairs must be even: key (string), value (any), ...
func appendFields(e *zerolog.Event, fields []any) *zerolog.Event {
	for i := 0; i+1 < len(fields); i += 2 {
		key, ok := fields[i].(string)
		if !ok {
			continue
		}
		e = e.Interface(key, fields[i+1])
	}
	return e
}
