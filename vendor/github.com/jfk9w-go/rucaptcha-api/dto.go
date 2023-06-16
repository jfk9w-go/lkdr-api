package rucaptcha

import "fmt"

type SolveIn interface {
	Method() string
}

type SolveOut struct {
	ID     string
	Answer string
}

type YandexSmartCaptchaIn struct {
	SiteKey                  string `url:"sitekey" validate:"required"`
	PageURL                  string `url:"pageurl" validate:"required"`
	AccessControlAllowOrigin bool   `url:"header_acao,omitempty"`
	UserAgent                string `url:"userAgent,omitempty"`
	Proxy                    string `url:"proxy,omitempty"`
	ProxyType                string `url:"proxytype,omitempty"`
}

func (in *YandexSmartCaptchaIn) Method() string {
	return "yandex"
}

type resIn interface {
	action() string
}

type resGetIn struct {
	ID string `url:"id"`
}

func (in *resGetIn) action() string {
	return "get"
}

type resReportIn struct {
	ID string `url:"id"`
	ok bool
}

func (in *resReportIn) action() string {
	if in.ok {
		return "reportgood"
	} else {
		return "reportbad"
	}
}

type Error struct {
	Code string
	Text string
}

func (e Error) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Text)
}
