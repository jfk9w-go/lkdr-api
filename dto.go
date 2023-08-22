package lkdr

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/jfk9w-go/based"
	"github.com/pkg/errors"
)

var dateTimeLocation = based.Lazy[*time.Location](
	func(ctx context.Context) (*time.Location, error) {
		return time.LoadLocation("Europe/Moscow")
	},
)

type DateTime time.Time

const dateTimeLayout = "2006-01-02T15:04:05"

func (dt DateTime) Time() time.Time {
	return time.Time(dt)
}

func (dt DateTime) MarshalJSON() ([]byte, error) {
	location, err := dateTimeLocation(context.Background())
	if err != nil {
		return nil, errors.Wrap(err, "load location")
	}

	str := dt.Time().In(location).Format(dateTimeLayout)
	return json.Marshal(str)
}

func (dt *DateTime) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}

	location, err := dateTimeLocation(context.Background())
	if err != nil {
		return errors.Wrap(err, "load location")
	}

	value, err := time.ParseInLocation(dateTimeLayout, str, location)
	if err != nil {
		return err
	}

	*dt = DateTime(value)
	return nil
}

type Date time.Time

const dateLayout = "2006-01-02"

func (d Date) Time() time.Time {
	return time.Time(d)
}

func (d Date) MarshalJSON() ([]byte, error) {
	location, err := dateTimeLocation(context.Background())
	if err != nil {
		return nil, errors.Wrap(err, "load location")
	}

	str := d.Time().In(location).Format(dateLayout)
	return json.Marshal(str)
}

func (d *Date) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}

	location, err := dateTimeLocation(context.Background())
	if err != nil {
		return errors.Wrap(err, "load location")
	}

	value, err := time.ParseInLocation(dateLayout, str, location)
	if err != nil {
		return err
	}

	*d = Date(value)
	return nil
}

type DateTimeTZ time.Time

func (dt DateTimeTZ) Time() time.Time {
	return time.Time(dt)
}

const dateTimeTZLayout = "2006-01-02T15:04:05.999Z"

func (dt DateTimeTZ) MarshalJSON() ([]byte, error) {
	str := dt.Time().Format(dateTimeTZLayout)
	return json.Marshal(str)
}

func (dt *DateTimeTZ) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}

	value, err := time.Parse(dateTimeTZLayout, str)
	if err != nil {
		return err
	}

	*dt = DateTimeTZ(value)
	return nil
}

type DateTimeMilliOffset time.Time

const dateTimeMilliOffsetLayout = "2006-01-02T15:04:05.999999-07:00"

func (dt DateTimeMilliOffset) Time() time.Time {
	return time.Time(dt)
}

func (dt DateTimeMilliOffset) MarshalJSON() ([]byte, error) {
	location, err := dateTimeLocation(context.Background())
	if err != nil {
		return nil, errors.Wrap(err, "load location")
	}

	str := dt.Time().In(location).Format(dateTimeMilliOffsetLayout)
	return json.Marshal(str)
}

func (dt *DateTimeMilliOffset) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}

	value, err := time.Parse(dateTimeMilliOffsetLayout, str)
	if err != nil {
		return err
	}

	*dt = DateTimeMilliOffset(value)
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

type exchange[R any] interface {
	auth() bool
	path() string
	out() R
}

type startIn struct {
	DeviceInfo   deviceInfo `json:"deviceInfo" validate:"required"`
	Phone        string     `json:"phone" validate:"required"`
	CaptchaToken string     `json:"captchaToken" validate:"required"`
}

func (in startIn) auth() bool        { return false }
func (in startIn) path() string      { return "/v2/auth/challenge/sms/start" }
func (in startIn) out() (_ startOut) { return }

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

func (in verifyIn) auth() bool      { return false }
func (in verifyIn) path() string    { return "/v1/auth/challenge/sms/verify" }
func (in verifyIn) out() (_ Tokens) { return }

type tokenIn struct {
	DeviceInfo   deviceInfo `json:"deviceInfo"`
	RefreshToken string     `json:"refreshToken" validate:"required"`
}

func (in tokenIn) auth() bool      { return false }
func (in tokenIn) path() string    { return "/v1/auth/token" }
func (in tokenIn) out() (_ Tokens) { return }

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

func (in ReceiptIn) auth() bool          { return true }
func (in ReceiptIn) path() string        { return "/v1/receipt" }
func (in ReceiptIn) out() (_ ReceiptOut) { return }

type Brand struct {
	Description string  `json:"description"`
	Id          int64   `json:"id"`
	Image       *string `json:"image"`
	Name        string  `json:"name"`
}

type Receipt struct {
	BrandId              *int64   `json:"brandId"`
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

func (in FiscalDataIn) auth() bool             { return true }
func (in FiscalDataIn) path() string           { return "/v1/receipt/fiscal_data" }
func (in FiscalDataIn) out() (_ FiscalDataOut) { return }

type ProviderData struct {
	ProviderPhone []string `json:"providerPhone"`
	ProviderName  string   `json:"providerName"`
}

type FiscalDataItem struct {
	Name         string        `json:"name"`
	Nds          int           `json:"nds"`
	PaymentType  int           `json:"paymentType"`
	Price        float64       `json:"price"`
	ProductType  int           `json:"productType"`
	ProviderData *ProviderData `json:"providerData"`
	ProviderInn  *string       `json:"providerInn"`
	Quantity     float64       `json:"quantity"`
	Sum          float64       `json:"sum"`
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
	InternetSign            *int             `json:"internetSign"`
	Items                   []FiscalDataItem `json:"items"`
	KktRegId                string           `json:"kktRegId"`
	MachineNumber           *string          `json:"machineNumber"`
	Nds10                   *float64         `json:"nds10"`
	Nds18                   *float64         `json:"nds18"`
	OperationType           int              `json:"operationType"`
	Operator                *string          `json:"operator"`
	PrepaidSum              float64          `json:"prepaidSum"`
	ProvisionSum            float64          `json:"provisionSum"`
	RequestNumber           int64            `json:"requestNumber"`
	RetailPlace             *string          `json:"retailPlace"`
	RetailPlaceAddress      *string          `json:"retailPlaceAddress"`
	ShiftNumber             int64            `json:"shiftNumber"`
	TaxationType            int              `json:"taxationType"`
	TotalSum                float64          `json:"totalSum"`
	User                    *string          `json:"user"`
	UserInn                 string           `json:"userInn"`
}
