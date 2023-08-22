package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/caarlos0/env"
	"github.com/jfk9w-go/based"
	"github.com/jfk9w-go/rucaptcha-api"
	"github.com/pkg/errors"

	"github.com/jfk9w-go/lkdr-api"
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

	if err := file.Truncate(0); err != nil {
		return errors.Wrap(err, "truncate file")
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

type authorizer struct {
	rucaptchaClient *rucaptcha.Client
}

func (a *authorizer) GetCaptchaToken(ctx context.Context, userAgent, siteKey, pageURL string) (string, error) {
	solved, err := a.rucaptchaClient.Solve(ctx, &rucaptcha.YandexSmartCaptchaIn{
		UserAgent: userAgent,
		SiteKey:   siteKey,
		PageURL:   pageURL,
	})

	if err != nil {
		return "", err
	}

	return solved.Answer, nil
}

func (a *authorizer) GetConfirmationCode(ctx context.Context, phone string) (string, error) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("Enter confirmation code for %s: ", phone)
	text, err := reader.ReadString('\n')
	if err != nil {
		return "", errors.Wrap(err, "read line from stdin")
	}

	return strings.Trim(text, " \n\t\v"), nil
}

func main() {
	var config struct {
		RucaptchaKey string `env:"RUCAPTCHA_KEY,required"`
		Phone        string `env:"LKDR_PHONE,required"`
		TokensFile   string `env:"LKDR_TOKENS_FILE,required"`
		DeviceID     string `env:"LKDR_DEVICE_ID,required"`
		UserAgent    string `env:"LKDR_USER_AGENT,required"`
	}

	if err := env.Parse(&config); err != nil {
		panic(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client, err := lkdr.ClientBuilder{
		Phone:     config.Phone,
		Clock:     based.StandardClock,
		DeviceID:  config.DeviceID,
		UserAgent: config.UserAgent,
		TokenStorage: jsonTokenStorage{
			path: config.TokensFile,
		},
	}.Build(ctx)

	if err != nil {
		panic(err)
	}

	rucaptchaClient, err := rucaptcha.ClientBuilder{
		Config: rucaptcha.Config{
			Key: config.RucaptchaKey,
		},
	}.Build()

	if err != nil {
		panic(err)
	}

	ctx = lkdr.WithAuthorizer(ctx, &authorizer{rucaptchaClient: rucaptchaClient})

	receipts, err := client.Receipt(ctx, &lkdr.ReceiptIn{
		Limit:   1,
		Offset:  0,
		OrderBy: "RECEIVE_DATE:DESC",
	})

	if err != nil {
		panic(err)
	}

	fmt.Printf("Last receipt key: %s\n", receipts.Receipts[0].Key)

	fiscalData, err := client.FiscalData(ctx, &lkdr.FiscalDataIn{
		Key: receipts.Receipts[0].Key,
	})

	if err != nil {
		panic(err)
	}

	fmt.Printf("First item in last receipt: %s\n", fiscalData.Items[0].Name)
}
