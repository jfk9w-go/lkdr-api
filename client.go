package lkdr

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"

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

type ClientParams struct {
	Phone        string       `validate:"required"`
	Clock        based.Clock  `validate:"required"`
	DeviceID     string       `validate:"required"`
	UserAgent    string       `validate:"required"`
	TokenStorage TokenStorage `validate:"required"`

	Transport http.RoundTripper
}

func NewClient(params ClientParams) (*Client, error) {
	if err := based.Validate(params); err != nil {
		return nil, err
	}

	return &Client{
		clock: params.Clock,
		phone: params.Phone,
		deviceInfo: deviceInfo{
			SourceType:     "WEB",
			SourceDeviceId: params.DeviceID,
			MetaDetails: metaDetails{
				UserAgent: params.UserAgent,
			},
			AppVersion: "1.0.0",
		},
		httpClient: &http.Client{
			Transport: params.Transport,
		},
		token: based.NewWriteThroughCached[string, *Tokens](
			based.WriteThroughCacheStorageFunc[string, *Tokens]{
				LoadFn:   params.TokenStorage.LoadTokens,
				UpdateFn: params.TokenStorage.UpdateTokens,
			},
			params.Phone,
		),
		mu: based.Semaphore(params.Clock, 20, time.Minute),
	}, nil
}

type Client struct {
	clock      based.Clock
	phone      string
	deviceInfo deviceInfo
	httpClient *http.Client
	token      *based.WriteThroughCached[*Tokens]
	mu         based.Locker
}

func (c *Client) Receipt(ctx context.Context, in *ReceiptIn) (*ReceiptOut, error) {
	return execute(ctx, c, in)
}

func (c *Client) FiscalData(ctx context.Context, in *FiscalDataIn) (*FiscalDataOut, error) {
	return execute(ctx, c, in)
}

func (c *Client) ensureToken(ctx context.Context) (string, error) {
	tokens, err := c.token.Get(ctx)
	if err != nil {
		return "", errors.Wrap(err, "load token")
	}

	now := c.clock.Now()
	updateToken := true
	if tokens == nil || tokens.RefreshTokenExpiresIn != nil && tokens.RefreshTokenExpiresIn.Time().Before(now.Add(expireTokenOffset)) {
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
	authorizer := getAuthorizer(ctx)
	if authorizer == nil {
		return nil, errors.New("authorizer is required, but not set")
	}

	captchaToken, err := authorizer.GetCaptchaToken(ctx, c.deviceInfo.MetaDetails.UserAgent, captchaSiteKey, captchaPageURL)
	if err != nil {
		return nil, errors.Wrap(err, "get captcha token")
	}

	startIn := &startIn{
		DeviceInfo:   c.deviceInfo,
		Phone:        c.phone,
		CaptchaToken: captchaToken,
	}

	startOut, err := execute(ctx, c, startIn)
	if err != nil {
		var clientErr Error
		if !errors.As(err, &clientErr) || clientErr.Code != SmsVerificationNotExpired {
			return nil, errors.Wrap(err, "start sms challenge")
		}
	}

	code, err := authorizer.GetConfirmationCode(ctx, c.phone)
	if err != nil {
		return nil, errors.Wrap(err, "get confirmation code")
	}

	verifyIn := &verifyIn{
		DeviceInfo:     c.deviceInfo,
		Phone:          c.phone,
		ChallengeToken: startOut.ChallengeToken,
		Code:           code,
	}

	tokens, err := execute(ctx, c, verifyIn)
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
