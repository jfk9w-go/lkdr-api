package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jfk9w-go/based"

	"github.com/jfk9w-go/lkdr-api"
	"github.com/jfk9w-go/rucaptcha-api"
	"github.com/pkg/errors"
)

type jsonTokenStorage struct {
	path string
}

func (s jsonTokenStorage) LoadTokens(ctx context.Context, phone string) (*lkdr.Tokens, error) {
	file, err := s.open(os.O_RDONLY)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}

		return nil, err
	}

	defer file.Close()
	contents := make(map[string]lkdr.Tokens)
	if err := json.NewDecoder(file).Decode(&contents); err != nil {
		return nil, errors.Wrap(err, "decode json")
	}

	if tokens, ok := contents[phone]; ok {
		return &tokens, nil
	}

	return nil, nil
}

func (s jsonTokenStorage) UpdateTokens(ctx context.Context, phone string, tokens *lkdr.Tokens) error {
	file, err := s.open(os.O_RDWR | os.O_CREATE)
	if err != nil {
		return err
	}

	stat, err := file.Stat()
	if err != nil {
		return errors.Wrap(err, "stat")
	}

	contents := make(map[string]lkdr.Tokens)
	if stat.Size() > 0 {
		if err := json.NewDecoder(file).Decode(&contents); err != nil {
			return errors.Wrap(err, "decode json")
		}
	}

	if tokens != nil {
		contents[phone] = *tokens
	} else {
		delete(contents, phone)
	}

	if _, err := file.Seek(0, 0); err != nil {
		return errors.Wrap(err, "seek to the start of file")
	}

	if err := json.NewEncoder(file).Encode(&contents); err != nil {
		return errors.Wrap(err, "encode json")
	}

	return nil
}

func (s jsonTokenStorage) open(flag int) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(s.path), os.ModeDir); err != nil {
		return nil, errors.Wrap(err, "create parent directory")
	}

	file, err := os.OpenFile(s.path, flag, 0644)
	if err != nil {
		return nil, errors.Wrap(err, "open file")
	}

	return file, nil
}

type rucaptchaTokenProvider struct {
	client  *rucaptcha.Client
	siteKey string
	pageURL string
}

func (p *rucaptchaTokenProvider) GetCaptchaToken(ctx context.Context) (string, error) {
	solved, err := p.client.Solve(ctx, &rucaptcha.YandexSmartCaptchaIn{
		SiteKey: p.siteKey,
		PageURL: p.pageURL,
	})

	if err != nil {
		return "", err
	}

	return solved.Answer, nil
}

type stdinConfirmationProvider struct{}

func (p stdinConfirmationProvider) GetConfirmationCode(ctx context.Context, phone string) (string, error) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("Enter confirmation code for %s: ", phone)
	text, err := reader.ReadString('\n')
	if err != nil {
		return "", errors.Wrap(err, "read line from stdin")
	}

	return strings.Trim(text, " \n\t\v"), nil
}

func main() {
	rucaptchaKey := os.Getenv("RUCAPTCHA_KEY")
	captchaSiteKey := os.Getenv("CAPTCHA_SITE_KEY")
	captchaPageURL := os.Getenv("CAPTCHA_PAGE_URL")
	lkdrPhone := os.Getenv("LKDR_PHONE")
	lkdrTokensFile := os.Getenv("LKDR_TOKENS_FILE")
	lkdrDeviceID := os.Getenv("LKDR_DEVICE_ID")
	lkdrUserAgent := os.Getenv("LKDR_USER_AGENT")

	for _, value := range []string{
		rucaptchaKey,
		captchaSiteKey,
		captchaPageURL,
		lkdrPhone,
		lkdrTokensFile,
		lkdrDeviceID,
		lkdrUserAgent,
	} {
		if value == "" {
			fmt.Println("RUCAPTCHA_KEY, CAPTCHA_SITE_KEY, CAPTCHA_PAGE_URL, LKDR_TOKENS_FILE, LKDR_TOKENS_FILE & LKDR_PHONE environment variables must not be empty")
			return
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	clock := based.StandardClock
	rucaptchaClient, err := rucaptcha.NewClient(clock, &rucaptcha.Config{
		Key: rucaptchaKey,
	})

	if err != nil {
		panic(err)
	}

	client := lkdr.ClientBuilder{
		Clock:     clock,
		DeviceID:  lkdrDeviceID,
		UserAgent: lkdrUserAgent,
		CaptchaTokenProvider: &rucaptchaTokenProvider{
			client:  rucaptchaClient,
			siteKey: captchaSiteKey,
			pageURL: captchaPageURL,
		},
		ConfirmationProvider: stdinConfirmationProvider{},
		TokenStorage: jsonTokenStorage{
			path: lkdrTokensFile,
		},
	}.Build()

	receipts, err := client.Receipt(ctx, lkdrPhone, &lkdr.ReceiptIn{
		Limit:   1,
		Offset:  0,
		OrderBy: "RECEIVE_DATE:DESC",
	})

	if err != nil {
		panic(err)
	}

	fmt.Printf("Last receipt key: %s\n", receipts.Receipts[0].Key)

	fiscalData, err := client.FiscalData(ctx, lkdrPhone, &lkdr.FiscalDataIn{
		Key: receipts.Receipts[0].Key,
	})

	if err != nil {
		panic(err)
	}

	fmt.Printf("First item in last receipt: %s\n", fiscalData.Items[0].Name)
}
