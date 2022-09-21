package util

import (
	"context"

	"github.com/sirupsen/logrus"
)

type (
	fieldsKey struct{}
	loggerKey struct{}
)

// FromContext returns a logger from the context. The Logger is configured with
// any fields set using WithField, or WithFields.
func FromContext(ctx context.Context) logrus.FieldLogger {
	logger := ctx.Value(loggerKey{})
	fields := getFields(ctx)
	if logger == nil {
		return logrus.StandardLogger().WithFields(fields)
	}
	return logger.(logrus.FieldLogger).WithFields(fields)
}

func getFields(ctx context.Context) logrus.Fields {
	fields := ctx.Value(fieldsKey{})
	if fields == nil {
		return logrus.Fields{}
	}
	return fields.(logrus.Fields)
}

// WithLogger creates a new Logger from fields, and sets it on the Context.
func WithLogger(ctx context.Context, logger logrus.FieldLogger) context.Context {
	return context.WithValue(ctx, loggerKey{}, logger)
}

// WithField adds the key and value to the context which will be added to the logger
// when retrieved with FromContext.
func WithField(ctx context.Context, key string, value interface{}) context.Context {
	existing := getFields(ctx)
	existing[key] = value
	return context.WithValue(ctx, fieldsKey{}, existing)
}

// WithFields adds fields to the context which will be added to the logger
// when retrieved with FromContext.
func WithFields(ctx context.Context, fields logrus.Fields) context.Context {
	existing := getFields(ctx)
	for k, v := range fields {
		existing[k] = v
	}
	return context.WithValue(ctx, fieldsKey{}, existing)
}
