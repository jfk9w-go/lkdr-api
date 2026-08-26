package lkdr

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestDateTimeJSON(t *testing.T) {
	location := time.FixedZone("UTC+3", 3*60*60)
	want := time.Date(2026, time.August, 25, 12, 34, 56, 0, location)

	data, err := json.Marshal(DateTime(want))
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if string(data) != `"2026-08-25T12:34:56"` {
		t.Errorf("Marshal() = %s", data)
	}

	var got DateTime
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if !got.Time().Equal(want) {
		t.Errorf("Unmarshal() = %v, want %v", got.Time(), want)
	}
}

func TestDateJSON(t *testing.T) {
	want := time.Date(2026, time.August, 25, 0, 0, 0, 0, time.FixedZone("UTC+3", 3*60*60))

	data, err := json.Marshal(Date(want))
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if string(data) != `"2026-08-25"` {
		t.Errorf("Marshal() = %s", data)
	}

	var got Date
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if !got.Time().Equal(want) {
		t.Errorf("Unmarshal() = %v, want %v", got.Time(), want)
	}
}

func TestDateTimeTZJSON(t *testing.T) {
	want := time.Date(2026, time.August, 25, 9, 34, 56, 123000000, time.UTC)

	data, err := json.Marshal(DateTimeTZ(want))
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if string(data) != `"2026-08-25T09:34:56.123Z"` {
		t.Errorf("Marshal() = %s", data)
	}

	var got DateTimeTZ
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if !got.Time().Equal(want) {
		t.Errorf("Unmarshal() = %v, want %v", got.Time(), want)
	}
}

func TestDateTimeMilliOffsetJSON(t *testing.T) {
	want := time.Date(2026, time.August, 25, 12, 34, 56, 123456000, time.FixedZone("UTC+3", 3*60*60))

	data, err := json.Marshal(DateTimeMilliOffset(want))
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if string(data) != `"2026-08-25T12:34:56.123456+03:00"` {
		t.Errorf("Marshal() = %s", data)
	}

	var got DateTimeMilliOffset
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if !got.Time().Equal(want) {
		t.Errorf("Unmarshal() = %v, want %v", got.Time(), want)
	}
}

func TestDateTypesRejectInvalidJSON(t *testing.T) {
	tests := []struct {
		name  string
		value any
	}{
		{name: "DateTime", value: new(DateTime)},
		{name: "Date", value: new(Date)},
		{name: "DateTimeTZ", value: new(DateTimeTZ)},
		{name: "DateTimeMilliOffset", value: new(DateTimeMilliOffset)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := json.Unmarshal([]byte(`"invalid"`), tt.value); err == nil {
				t.Fatal("Unmarshal() error = nil")
			}
		})
	}
}

func TestError(t *testing.T) {
	tests := []struct {
		name string
		err  Error
		want string
	}{
		{name: "code and message", err: Error{Code: BlockedCaptcha, Message: "blocked"}, want: "blocked.captcha (blocked)"},
		{name: "code", err: Error{Code: BlockedCaptcha}, want: "blocked.captcha"},
		{name: "message", err: Error{Message: "failed"}, want: "failed"},
		{name: "empty", err: Error{}, want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIsDataNotFound(t *testing.T) {
	if IsDataNotFound(errors.New("wrapped: " + Error{Code: ReceiptFiscalDataNotFound}.Error())) {
		t.Fatal("IsDataNotFound() accepted an untyped error")
	}

	if !IsDataNotFound(Error{Code: ReceiptFiscalDataNotFound}) {
		t.Fatal("IsDataNotFound() = false for ReceiptFiscalDataNotFound")
	}
	if IsDataNotFound(Error{Code: BlockedCaptcha}) {
		t.Fatal("IsDataNotFound() = true for a different code")
	}
}
