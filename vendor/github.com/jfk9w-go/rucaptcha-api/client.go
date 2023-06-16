package rucaptcha

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/url"

	"github.com/go-playground/validator"
	"github.com/google/go-querystring/query"
	"github.com/jfk9w-go/based"
	"github.com/pkg/errors"
)

const baseURL = "https://rucaptcha.com"

type Config struct {
	Key      string `url:"key" validate:"required"`
	Pingback string `url:"pingback,omitempty"`
	SoftID   int    `url:"soft_id,omitempty"`
}

var validate = based.Lazy[*validator.Validate]{
	Fn: func(ctx context.Context) (*validator.Validate, error) {
		return validator.New(), nil
	},
}

type ClientBuilder struct {
	Config Config      `validate:"required"`
	Clock  based.Clock `validate:"required_with=Config.Pingback"`

	Transport http.RoundTripper
}

func (b ClientBuilder) Build(ctx context.Context) (*Client, error) {
	if validate, err := validate.Get(ctx); err != nil {
		return nil, err
	} else if err := validate.Struct(b); err != nil {
		return nil, err
	}

	options, err := query.Values(b.Config)
	if err != nil {
		return nil, errors.Wrap(err, "encode options")
	}

	options.Set("json", "1")

	client := &Client{
		httpClient: &http.Client{
			Transport: b.Transport,
		},
		options: options,
	}

	if b.Config.Pingback == "" {
		client.answerer = &answerPoller{client}
	} else {
		client.answerer = newAsyncListener(b.Clock)
	}

	return client, nil
}

type Client struct {
	httpClient *http.Client
	answerer   answerer
	options    url.Values
}

func (c *Client) HTTPHandler() http.Handler {
	if handler, ok := c.answerer.(http.Handler); ok {
		return handler
	}

	return nil
}

func (c *Client) Solve(ctx context.Context, in SolveIn) (*SolveOut, error) {
	if validate, err := validate.Get(ctx); err != nil {
		return nil, err
	} else if err := validate.Struct(in); err != nil {
		return nil, err
	}

	values, err := query.Values(in)
	if err != nil {
		return nil, errors.Wrap(err, "encode solve values")
	}

	values.Set("method", in.Method())
	id, err := c.execute(ctx, "/in.php", values)
	if err != nil {
		return nil, errors.Wrap(err, "send solve request")
	}

	answer, err := c.answerer.answer(ctx, id)
	if err != nil {
		return nil, errors.Wrap(err, "get answer")
	}

	return &SolveOut{
		ID:     id,
		Answer: answer,
	}, nil
}

func (c *Client) Report(ctx context.Context, id string, ok bool) error {
	in := &resReportIn{
		ID: id,
		ok: ok,
	}

	_, err := c.res(ctx, in)
	return err
}

func (c *Client) res(ctx context.Context, in resIn) (string, error) {
	values, err := query.Values(in)
	if err != nil {
		return "", errors.Wrap(err, "encode solve values")
	}

	values.Set("action", in.action())
	result, err := c.execute(ctx, "/res.php", values)
	if err != nil {
		return "", errors.Wrap(err, "send res request")
	}

	return result, nil
}

func (c *Client) execute(ctx context.Context, path string, query url.Values) (string, error) {
	var reqBody bytes.Buffer
	multipartWriter := multipart.NewWriter(&reqBody)
	for _, params := range []url.Values{c.options, query} {
		for key, values := range params {
			for _, value := range values {
				if err := multipartWriter.WriteField(key, value); err != nil {
					_ = multipartWriter.Close()
					return "", errors.Wrapf(err, "write '%s' to request body", key)
				}
			}
		}
	}

	if err := multipartWriter.Close(); err != nil {
		return "", errors.Wrap(err, "close writer")
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+path, &reqBody)
	if err != nil {
		return "", errors.Wrap(err, "create request")
	}

	httpReq.Header.Set("Content-Type", multipartWriter.FormDataContentType())

	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return "", errors.Wrap(err, "execute request")
	}

	if httpResp.StatusCode != http.StatusOK {
		return "", errors.Errorf(httpResp.Status)
	}

	if httpResp.Body == nil {
		return "", errors.New("empty response body")
	}

	defer httpResp.Body.Close()

	var respBody struct {
		Status    *int   `json:"status"`
		Request   string `json:"request"`
		ErrorText string `json:"error_text"`
	}

	if err := json.NewDecoder(httpResp.Body).Decode(&respBody); err != nil {
		return "", errors.Wrap(err, "read response json")
	}

	switch {
	case respBody.Status == nil:
		return "", errors.New("empty status")
	case *respBody.Status == 0:
		return "", &Error{Code: respBody.Request, Text: respBody.ErrorText}
	default:
		return respBody.Request, nil
	}
}
