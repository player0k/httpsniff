//go:build !windows && !linux && !darwin

package proxy

import (
	"errors"

	"httpsniff/internal/i18n"
)

// ServeTransparent — заглушка: прозрачный режим не поддержан на этой платформе.
func (p *Proxy) ServeTransparent(addr string, tport int) (func(), error) {
	return nil, errors.New(i18n.T("proxy.errTransparentUnsupported"))
}
