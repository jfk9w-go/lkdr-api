package rucaptcha

import (
	"context"
	"math"
	"net/http"
	"sync"
	"time"

	"github.com/jfk9w-go/based"

	"github.com/pkg/errors"
)

type answerer interface {
	answer(ctx context.Context, requestID string) (string, error)
}

type resClient interface {
	res(ctx context.Context, in resIn) (string, error)
}

type answerPoller struct {
	client resClient
}

func (p *answerPoller) answer(ctx context.Context, requestID string) (string, error) {
	in := &resGetIn{
		ID: requestID,
	}

	timeout := 10 * time.Second
	for {
		select {
		case <-time.After(timeout):
			result, err := p.client.res(ctx, in)
			if err == nil {
				return result, nil
			}

			var clientErr Error
			if errors.As(err, &clientErr) && clientErr.Code != "CAPCHA_NOT_READY" {
				return "", err
			}

			timeout = time.Duration(math.Max(float64(timeout)/2, 2))

		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
}

type asyncAnswer struct {
	c       chan string
	created time.Time
}

type answerListener struct {
	clock   based.Clock
	answers map[string]asyncAnswer
	mu      sync.Mutex
}

func newAsyncListener(clock based.Clock) *answerListener {
	return &answerListener{
		clock:   clock,
		answers: make(map[string]asyncAnswer),
	}
}

func (pb *answerListener) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	id := req.FormValue("id")
	code := req.FormValue("code")
	if id == "" || code == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	answer := pb.getAsyncAnswer(id)
	select {
	case answer.c <- code:
		w.WriteHeader(http.StatusOK)
	case <-req.Context().Done():
		w.WriteHeader(http.StatusUnprocessableEntity)
	}
}

func (pb *answerListener) answer(ctx context.Context, id string) (string, error) {
	answer := pb.getAsyncAnswer(id)
	select {
	case result := <-answer.c:
		return result, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func (pb *answerListener) getAsyncAnswer(id string) asyncAnswer {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	now := pb.clock.Now()
	ans, ok := pb.answers[id]
	if !ok {
		ans = asyncAnswer{
			c:       make(chan string, 1),
			created: now,
		}

		pb.answers[id] = ans
	}

	for id, ans := range pb.answers {
		if now.Sub(ans.created) > 5*time.Minute {
			close(ans.c)
			delete(pb.answers, id)
		}
	}

	return ans
}
