package util

import (
	"context"
	"errors"
	"log/slog"
)

func newMultilogHandler(h ...slog.Handler) slog.Handler {
	return &multiloghandler{
		handlers: h,
	}
}

type multiloghandler struct {
	handlers []slog.Handler
}

func (l *multiloghandler) Enabled(ctx context.Context, level slog.Level) bool {
	for i := range l.handlers {
		if l.handlers[i].Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (l *multiloghandler) Handle(ctx context.Context, record slog.Record) error {
	var errs []error
	for i := range l.handlers {
		if l.handlers[i].Enabled(ctx, record.Level) {
			if err := l.handlers[i].Handle(ctx, record); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}
func (l *multiloghandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	handlers := make([]slog.Handler, 0, len(l.handlers))
	for i := range l.handlers {
		handlers = append(handlers, l.handlers[i].WithAttrs(attrs))
	}
	return newMultilogHandler(handlers...)
}
func (l *multiloghandler) WithGroup(name string) slog.Handler {
	handlers := make([]slog.Handler, 0, len(l.handlers))
	for i := range l.handlers {
		handlers = append(handlers, l.handlers[i].WithGroup(name))
	}
	return newMultilogHandler(handlers...)
}
