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
	Clock                based.Clock          `validate:"required"`
	DeviceID             string               `validate:"required"`
	UserAgent            string               `validate:"required"`
	ConfirmationProvider ConfirmationProvider `validate:"required"`
	TokenStorage         TokenStorage         `validate:"required"`

	CaptchaTokenProvider CaptchaTokenProvider
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
		tokenCache: based.NewWriteThroughCache[string, *Tokens](
			based.WriteThroughCacheStorageFunc[string, *Tokens]{
				LoadFn:   b.TokenStorage.LoadTokens,
				UpdateFn: b.TokenStorage.UpdateTokens,
			},
		),
	}, nil
}

type Client struct {
	clock                based.Clock
	deviceInfo           deviceInfo
	httpClient           *http.Client
	captchaTokenProvider CaptchaTokenProvider
	confirmationProvider ConfirmationProvider
	tokenCache           *based.WriteThroughCache[string, *Tokens]
}

func (c *Client) Receipt(ctx context.Context, phone string, in *ReceiptIn) (*ReceiptOut, error) {
	var out ReceiptOut
	if err := c.executeAuthorized(ctx, phone, "/v1/receipt", in, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

func (c *Client) FiscalData(ctx context.Context, phone string, in *FiscalDataIn) (*FiscalDataOut, error) {
	var out FiscalDataOut
	if err := c.executeAuthorized(ctx, phone, "/v1/receipt/fiscal_data", in, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

func (c *Client) executeAuthorized(ctx context.Context, phone, path string, in, out any) error {
	tokens, err := c.tokenCache.Get(ctx, phone)
	if err != nil {
		return errors.Wrap(err, "load token")
	}

	now := c.clock.Now()
	updateToken := true
	if tokens == nil || tokens.RefreshTokenExpiresIn != nil &&
		pointer.Get[DateTimeTZ](tokens.RefreshTokenExpiresIn).Time().Before(now.Add(expireTokenOffset)) {
		tokens, err = c.authorize(ctx, phone)
		if err != nil {
			return errors.Wrap(err, "authorize")
		}
	} else if tokens.TokenExpireIn.Time().Before(now.Add(expireTokenOffset)) {
		tokens, err = c.refreshToken(ctx, tokens.RefreshToken)
		if err != nil {
			return errors.Wrap(err, "refresh token")
		}
	} else {
		updateToken = false
	}

	if updateToken {
		if err := c.tokenCache.Update(ctx, phone, tokens); err != nil {
			return errors.Wrap(err, "update token")
		}
	}

	if err := c.execute(ctx, path, tokens.Token, in, out); err != nil {
		return errors.Wrap(err, "execute request")
	}

	return nil
}

func (c *Client) authorize(ctx context.Context, phone string) (*Tokens, error) {
	if c.captchaTokenProvider == nil {
		return nil, errors.New("captcha token provider not set")
	}

	captchaToken, err := c.captchaTokenProvider.GetCaptchaToken(ctx, c.deviceInfo.MetaDetails.UserAgent, captchaSiteKey, captchaPageURL)
	if err != nil {
		return nil, errors.Wrap(err, "get captcha token")
	}

	startIn := &startIn{
		DeviceInfo:   c.deviceInfo,
		Phone:        phone,
		CaptchaToken: captchaToken,
	}

	var startOut startOut
	if err := c.execute(ctx, "/v2/auth/challenge/sms/start", "", startIn, &startOut); err != nil {
		var clientErr Error
		if !errors.As(err, &clientErr) || clientErr.Code != SmsVerificationNotExpired {
			return nil, errors.Wrap(err, "start sms challenge")
		}
	}

	code, err := c.confirmationProvider.GetConfirmationCode(ctx, phone)
	if err != nil {
		return nil, errors.Wrap(err, "get confirmation code")
	}

	verifyIn := &verifyIn{
		DeviceInfo:     c.deviceInfo,
		Phone:          phone,
		ChallengeToken: startOut.ChallengeToken,
		Code:           code,
	}

	var tokens Tokens
	if err := c.execute(ctx, "/v1/auth/challenge/sms/verify", "", verifyIn, &tokens); err != nil {
		return nil, errors.Wrap(err, "verify code")
	}

	return &tokens, nil
}

func (c *Client) refreshToken(ctx context.Context, refreshToken string) (*Tokens, error) {
	in := &tokenIn{
		DeviceInfo:   c.deviceInfo,
		RefreshToken: refreshToken,
	}

	var out Tokens
	if err := c.execute(ctx, "/v1/auth/token", "", in, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

func (c *Client) execute(ctx context.Context, path, token string, in, out any) error {
	reqBody, err := json.Marshal(in)
	if err != nil {
		return errors.Wrap(err, "marshal json body")
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+path, bytes.NewReader(reqBody))
	if err != nil {
		return errors.Wrap(err, "create request")
	}

	httpReq.Header.Set("Content-Type", "application/json;charset=UTF-8")
	if token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+token)
	}

	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return errors.Wrap(err, "execute request")
	}

	if httpResp.Body == nil {
		return errors.New(httpResp.Status)
	}

	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		var clientErr Error
		if err := json.NewDecoder(httpResp.Body).Decode(&clientErr); err == nil {
			return clientErr
		}

		return errors.New(httpResp.Status)
	}

	if err := json.NewDecoder(httpResp.Body).Decode(out); err != nil {
		return errors.Wrap(err, "decode response body")
	}

	return nil
}
