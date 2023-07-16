package lkdr

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/AlekSi/pointer"
	"github.com/go-playground/validator"
	"github.com/jfk9w-go/based"
	"github.com/pkg/errors"
	"go.uber.org/multierr"
)

const (
	baseURL           = "https://mco.nalog.ru/api"
	expireTokenOffset = 5 * time.Minute
	captchaSiteKey    = "hfU4TD7fJUI7XcP5qRphKWgnIR5t9gXAxTRqdQJk"
	captchaPageURL    = "https://lkdr.nalog.ru/login"
)

type TokenStorage interface {
	LoadTokens(ctx context.Context, phone string) (*Tokens, error)
	UpdateTokens(ctx context.Context, phone string, tokens *Tokens) error
}

type ConfirmationProvider interface {
	GetConfirmationCode(ctx context.Context, phone string) (string, error)
}

type CaptchaTokenProvider interface {
	GetCaptchaToken(ctx context.Context, userAgent, siteKey, pageURL string) (string, error)
}

var validate = based.Lazy[*validator.Validate]{
	Fn: func(ctx context.Context) (*validator.Validate, error) {
		return validator.New(), nil
	},
}

type ClientBuilder struct {
	Phone        string       `validate:"required"`
	Clock        based.Clock  `validate:"required"`
	DeviceID     string       `validate:"required"`
	UserAgent    string       `validate:"required"`
	TokenStorage TokenStorage `validate:"required"`

	CaptchaTokenProvider CaptchaTokenProvider
	ConfirmationProvider ConfirmationProvider
	Transport            http.RoundTripper
}

func (b ClientBuilder) Build(ctx context.Context) (*Client, error) {
	if validate, err := validate.Get(ctx); err != nil {
		return nil, err
	} else if err := validate.Struct(b); err != nil {
		return nil, err
	}

	return &Client{
		clock: b.Clock,
		phone: b.Phone,
		deviceInfo: deviceInfo{
			SourceType:     "WEB",
			SourceDeviceId: b.DeviceID,
			MetaDetails: metaDetails{
				UserAgent: b.UserAgent,
			},
			AppVersion: "1.0.0",
		},
		httpClient: &http.Client{
			Transport: b.Transport,
		},
		captchaTokenProvider: b.CaptchaTokenProvider,
		confirmationProvider: b.ConfirmationProvider,
		token: based.NewWriteThroughCached[string, *Tokens](
			based.WriteThroughCacheStorageFunc[string, *Tokens]{
				LoadFn:   b.TokenStorage.LoadTokens,
				UpdateFn: b.TokenStorage.UpdateTokens,
			},
			b.Phone,
		),
		mu: based.Semaphore(b.Clock, 20, time.Minute),
	}, nil
}

type Client struct {
	clock                based.Clock
	phone                string
	deviceInfo           deviceInfo
	httpClient           *http.Client
	captchaTokenProvider CaptchaTokenProvider
	confirmationProvider ConfirmationProvider
	token                *based.WriteThroughCached[*Tokens]
	mu                   based.Locker
}

func (c *Client) Receipt(ctx context.Context, in *ReceiptIn) (*ReceiptOut, error) {
	return execute[ReceiptOut](ctx, c, in)
}

func (c *Client) FiscalData(ctx context.Context, in *FiscalDataIn) (*FiscalDataOut, error) {
	return execute[FiscalDataOut](ctx, c, in)
}

func (c *Client) ensureToken(ctx context.Context) (string, error) {
	tokens, err := c.token.Get(ctx)
	if err != nil {
		return "", errors.Wrap(err, "load token")
	}

	now := c.clock.Now()
	updateToken := true
	if tokens == nil || tokens.RefreshTokenExpiresIn != nil &&
		pointer.Get[DateTimeTZ](tokens.RefreshTokenExpiresIn).Time().Before(now.Add(expireTokenOffset)) {
		tokens, err = c.authorize(ctx)
		if err != nil {
			return "", errors.Wrap(err, "authorize")
		}
	} else if tokens.TokenExpireIn.Time().Before(now.Add(expireTokenOffset)) {
		tokens, err = c.refreshToken(ctx, tokens.RefreshToken)
		if err != nil {
			return "", errors.Wrap(err, "refresh token")
		}
	} else {
		updateToken = false
	}

	if updateToken {
		if err := c.token.Update(ctx, tokens); err != nil {
			return "", errors.Wrap(err, "update token")
		}
	}

	return tokens.Token, nil
}

func (c *Client) authorize(ctx context.Context) (*Tokens, error) {
	var err error

	if c.captchaTokenProvider == nil {
		err = multierr.Append(err, errors.New("captcha token provider not set"))
	}

	if c.confirmationProvider == nil {
		err = multierr.Append(err, errors.New("confirmation provider not set"))
	}

	if err != nil {
		return nil, err
	}

	captchaToken, err := c.captchaTokenProvider.GetCaptchaToken(ctx, c.deviceInfo.MetaDetails.UserAgent, captchaSiteKey, captchaPageURL)
	if err != nil {
		return nil, errors.Wrap(err, "get captcha token")
	}

	startIn := &startIn{
		DeviceInfo:   c.deviceInfo,
		Phone:        c.phone,
		CaptchaToken: captchaToken,
	}

	startOut, err := execute[startOut](ctx, c, startIn)
	if err != nil {
		var clientErr Error
		if !errors.As(err, &clientErr) || clientErr.Code != SmsVerificationNotExpired {
			return nil, errors.Wrap(err, "start sms challenge")
		}
	}

	code, err := c.confirmationProvider.GetConfirmationCode(ctx, c.phone)
	if err != nil {
		return nil, errors.Wrap(err, "get confirmation code")
	}

	verifyIn := &verifyIn{
		DeviceInfo:     c.deviceInfo,
		Phone:          c.phone,
		ChallengeToken: startOut.ChallengeToken,
		Code:           code,
	}

	tokens, err := execute[Tokens](ctx, c, verifyIn)
	if err != nil {
		return nil, errors.Wrap(err, "verify code")
	}

	return tokens, nil
}

func (c *Client) refreshToken(ctx context.Context, refreshToken string) (*Tokens, error) {
	in := &tokenIn{
		DeviceInfo:   c.deviceInfo,
		RefreshToken: refreshToken,
	}

	return execute[Tokens](ctx, c, in)
}

func execute[R any](ctx context.Context, c *Client, in exchange[R]) (*R, error) {
	var token string
	if in.auth() {
		var (
			cancel context.CancelFunc
			err    error
		)

		ctx, cancel = c.mu.Lock(ctx)
		defer cancel()
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		token, err = c.ensureToken(ctx)
		if err != nil {
			return nil, err
		}
	}

	reqBody, err := json.Marshal(in)
	if err != nil {
		return nil, errors.Wrap(err, "marshal json body")
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+in.path(), bytes.NewReader(reqBody))
	if err != nil {
		return nil, errors.Wrap(err, "create request")
	}

	httpReq.Header.Set("Content-Type", "application/json;charset=UTF-8")
	if token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+token)
	}

	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, errors.Wrap(err, "execute request")
	}

	if httpResp.Body == nil {
		return nil, errors.New(httpResp.Status)
	}

	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		var clientErr Error
		if err := json.NewDecoder(httpResp.Body).Decode(&clientErr); err == nil {
			return nil, clientErr
		}

		return nil, errors.New(httpResp.Status)
	}

	var out R
	if err := json.NewDecoder(httpResp.Body).Decode(&out); err != nil {
		return nil, errors.Wrap(err, "decode response body")
	}

	return &out, nil
}
