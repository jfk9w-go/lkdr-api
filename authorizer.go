package lkdr

import "context"

type Authorizer interface {
	GetCaptchaToken(ctx context.Context, userAgent, siteKey, pageURL string) (string, error)
	GetConfirmationCode(ctx context.Context, phone string) (string, error)
}

type authorizerKey struct{}

func WithAuthorizer(ctx context.Context, authorizer Authorizer) context.Context {
	return context.WithValue(ctx, authorizerKey{}, authorizer)
}

func getAuthorizer(ctx context.Context) Authorizer {
	authorizer, _ := ctx.Value(authorizerKey{}).(Authorizer)
	return authorizer
}
