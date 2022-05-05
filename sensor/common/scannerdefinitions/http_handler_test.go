package scannerdefinitions

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

type responseWriterMock struct {
	bytes.Buffer
	statusCode int
	headers    http.Header
}

func NewMockResponseWriter() *responseWriterMock {
	return &responseWriterMock{
		headers: make(http.Header),
	}
}

func (m *responseWriterMock) Header() http.Header {
	return m.headers
}

func (m *responseWriterMock) WriteHeader(statusCode int) {
	m.statusCode = statusCode
}

// transportMockFunc is a transport mock that call itself to implement http.Transport's RoundTrip.
type transportMockFunc func(req *http.Request) (*http.Response, error)

func (f transportMockFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func Test_scannerDefinitionsHandler_ServeHTTP(t *testing.T) {
	testRequest := http.Request{
		Method: http.MethodGet,
		URL:    &url.URL{RawQuery: "bar=1&foo=2"},
		Header: map[string][]string{"If-Modified-Since": {"1209"}, "Accept-Encoding": {""}},
	}
	type args struct {
		writer  *responseWriterMock
		request *http.Request
	}
	tests := []struct {
		name         string
		args         args
		responseBody string
		statusCode   int
	}{
		{
			name:         "when central replies 200 with content then writer matches",
			statusCode:   200,
			responseBody: "the foobar body.",
			args: args{
				writer: NewMockResponseWriter(),
			},
		},
		{
			name:         "when central replies 304 then writer matches",
			statusCode:   304,
			responseBody: "",
			args: args{
				writer: NewMockResponseWriter(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.args.request == nil {
				tt.args.request = &testRequest
			}
			h := &scannerDefinitionsHandler{
				centralClient: &http.Client{
					Transport: transportMockFunc(func(req *http.Request) (*http.Response, error) {
						assert.Equal(t, tt.args.request.URL.RawQuery, req.URL.RawQuery)
						for _, header := range headersToProxy.AsSlice() {
							assert.Equal(t, tt.args.request.Header[header], req.Header[header])
						}
						return &http.Response{
							StatusCode: tt.statusCode,
							Body:       io.NopCloser(bytes.NewBufferString(tt.responseBody)),
						}, nil
					}),
				},
			}
			h.ServeHTTP(tt.args.writer, tt.args.request)
			assert.Equal(t, tt.responseBody, tt.args.writer.String())
			assert.Equal(t, tt.statusCode, tt.args.writer.statusCode)
		})
	}
}
