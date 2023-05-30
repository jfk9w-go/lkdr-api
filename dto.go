package lkdr

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/jfk9w-go/based"
	"github.com/pkg/errors"
)

var dateTimeLocation = &based.Lazy[*time.Location]{
	Fn: func(ctx context.Context) (*time.Location, error) {
		return time.LoadLocation("Europe/Moscow")
	},
}

type DateTime struct {
	time.Time
}

func (dt *DateTime) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}

	location, err := dateTimeLocation.Get(context.Background())
	if err != nil {
		return errors.Wrap(err, "load location")
	}

	value, err := time.ParseInLocation("2006-01-02T15:04:05", str, location)
	if err != nil {
		return err
	}

	dt.Time = value
	return nil
}

type Date struct {
	time.Time
}

func (d Date) MarshalJSON() ([]byte, error) {
	location, err := dateTimeLocation.Get(context.Background())
	if err != nil {
		return nil, errors.Wrap(err, "load location")
	}

	str := d.Time.In(location).Format("2006-01-02")
	return json.Marshal(str)
}

type DateTimeTZ struct {
	time.Time
}

func (dt *DateTimeTZ) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}

	value, err := time.Parse("2006-01-02T15:04:05.999Z", str)
	if err != nil {
		return err
	}

	dt.Time = value
	return nil
}

type DateTimeMilliOffset struct {
	time.Time
}

func (dt *DateTimeMilliOffset) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}

	value, err := time.Parse("2006-01-02T15:04:05.999999-07:00", str)
	if err != nil {
		return err
	}

	dt.Time = value
	return nil
}

type ErrorCode string

const (
	SmsVerificationNotExpired ErrorCode = "registration.sms.verification.not.expired"
	BlockedCaptcha            ErrorCode = "blocked.captcha"
)

type Error struct {
	Code    ErrorCode `json:"code"`
	Message string    `json:"message"`
}

func (e Error) Error() string {
	var b strings.Builder
	if e.Code != "" {
		b.WriteString(string(e.Code))
		if e.Message != "" {
			b.WriteString(" (" + e.Message + ")")
		}
	} else if e.Message != "" {
		b.WriteString(e.Message)
	}

	return b.String()
}

type metaDetails struct {
	UserAgent string `json:"userAgent"`
}

type deviceInfo struct {
	AppVersion     string      `json:"appVersion" validate:"required"`
	MetaDetails    metaDetails `json:"metaDetails"`
	SourceDeviceId string      `json:"sourceDeviceId" validate:"required"`
	SourceType     string      `json:"sourceType" validate:"required"`
}

type startIn struct {
	DeviceInfo   deviceInfo `json:"deviceInfo" validate:"required"`
	Phone        string     `json:"phone" validate:"required"`
	CaptchaToken string     `json:"captchaToken" validate:"required"`
}

type startOut struct {
	ChallengeToken             string              `json:"challengeToken"`
	ChallengeTokenExpiresIn    DateTimeMilliOffset `json:"challengeTokenExpiresIn"`
	ChallengeTokenExpiresInSec int                 `json:"challengeTokenExpiresInSec"`
}

type verifyIn struct {
	DeviceInfo     deviceInfo `json:"deviceInfo"`
	Phone          string     `json:"phone" validate:"required"`
	ChallengeToken string     `json:"challengeToken" validate:"required"`
	Code           string     `json:"code" validate:"required"`
}

type tokenIn struct {
	DeviceInfo   deviceInfo `json:"deviceInfo"`
	RefreshToken string     `json:"refreshToken" validate:"required"`
}

type Tokens struct {
	RefreshToken          string      `json:"refreshToken"`
	RefreshTokenExpiresIn *DateTimeTZ `json:"refreshTokenExpiresIn,omitempty"`
	Token                 string      `json:"token"`
	TokenExpireIn         DateTimeTZ  `json:"tokenExpireIn"`
}

type ReceiptIn struct {
	DateFrom *Date   `json:"dateFrom"`
	DateTo   *Date   `json:"dateTo"`
	Inn      *string `json:"inn"`
	KktOwner string  `json:"kktOwner"`
	Limit    int     `json:"limit"`
	Offset   int     `json:"offset"`
	OrderBy  string  `json:"orderBy"`
}

type Brand struct {
	Description string `json:"description"`
	ID          int64  `json:"id"`
	Image       string `json:"image"`
	Name        string `json:"name"`
}

type Receipt struct {
	BrandId              int64    `json:"brandId"`
	Buyer                string   `json:"buyer"`
	BuyerType            string   `json:"buyerType"`
	CreatedDate          DateTime `json:"createdDate"`
	FiscalDocumentNumber string   `json:"fiscalDocumentNumber"`
	FiscalDriveNumber    string   `json:"fiscalDriveNumber"`
	Key                  string   `json:"key"`
	KktOwner             string   `json:"kktOwner"`
	KktOwnerInn          string   `json:"kktOwnerInn"`
	ReceiveDate          DateTime `json:"receiveDate"`
	TotalSum             string   `json:"totalSum"`
}

type ReceiptOut struct {
	Brands   []Brand   `json:"brands"`
	Receipts []Receipt `json:"receipts"`
	HasMore  bool      `json:"hasMore"`
}

type FiscalDataIn struct {
	Key string `json:"key"`
}

type FiscalDataItem struct {
	Name        string  `json:"name"`
	Nds         int     `json:"nds"`
	PaymentType int     `json:"paymentType"`
	Price       float64 `json:"price"`
	ProductType int     `json:"productType"`
	ProviderInn string  `json:"providerInn"`
	Quantity    float64 `json:"quantity"`
	Sum         float64 `json:"sum"`
}

type FiscalDataOut struct {
	BuyerAddress            string           `json:"buyerAddress"`
	CashTotalSum            float64          `json:"cashTotalSum"`
	CreditSum               float64          `json:"creditSum"`
	DateTime                DateTime         `json:"dateTime"`
	EcashTotalSum           float64          `json:"ecashTotalSum"`
	FiscalDocumentFormatVer string           `json:"fiscalDocumentFormatVer"`
	FiscalDocumentNumber    int64            `json:"fiscalDocumentNumber"`
	FiscalDriveNumber       string           `json:"fiscalDriveNumber"`
	FiscalSign              string           `json:"fiscalSign"`
	InternetSign            int              `json:"internetSign"`
	Items                   []FiscalDataItem `json:"items"`
	KktRegId                string           `json:"kktRegId"`
	MachineNumber           string           `json:"machineNumber"`
	Nds10                   float64          `json:"nds10"`
	Nds18                   float64          `json:"nds18"`
	OperationType           int              `json:"operationType"`
	PrepaidSum              float64          `json:"prepaidSum"`
	ProvisionSum            float64          `json:"provisionSum"`
	RequestNumber           int64            `json:"requestNumber"`
	RetailPlace             string           `json:"retailPlace"`
	RetailPlaceAddress      string           `json:"retailPlaceAddress"`
	ShiftNumber             int64            `json:"shiftNumber"`
	TaxationType            int              `json:"taxationType"`
	TotalSum                float64          `json:"totalSum"`
	User                    string           `json:"user"`
	UserInn                 string           `json:"userInn"`
}
