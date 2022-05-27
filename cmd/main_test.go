package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/go-kit/log"
	"github.com/prometheus/prometheus/model/exemplar"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/prompb"
	"github.com/prometheus/prometheus/storage"
	"github.com/prometheus/prometheus/storage/remote"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var writeRequestFixture = &prompb.WriteRequest{
	Timeseries: []prompb.TimeSeries{
		{
			Labels: []prompb.Label{
				{Name: "__name__", Value: "test_metric1"},
				{Name: "b", Value: "c"},
				{Name: "baz", Value: "qux"},
				{Name: "d", Value: "e"},
				{Name: "foo", Value: "bar"},
			},
			Samples:   []prompb.Sample{{Value: 1, Timestamp: 0}},
			Exemplars: []prompb.Exemplar{{Labels: []prompb.Label{{Name: "f", Value: "g"}}, Value: 1, Timestamp: 0}},
		},
		{
			Labels: []prompb.Label{
				{Name: "__name__", Value: "test_metric1"},
				{Name: "b", Value: "c"},
				{Name: "baz", Value: "qux"},
				{Name: "d", Value: "e"},
				{Name: "foo", Value: "bar"},
			},
			Samples:   []prompb.Sample{{Value: 2, Timestamp: 1}},
			Exemplars: []prompb.Exemplar{{Labels: []prompb.Label{{Name: "h", Value: "i"}}, Value: 2, Timestamp: 1}},
		},
	},
}

func TestRemoteWrite(t *testing.T) {
	t.Run("happy case", func(t *testing.T) {
		logger := log.NewNopLogger()

		appendable := &mockAppendable{}
		remoteWriteHandler := remote.NewWriteHandler(nil, appendable)
		remoteServer := httptest.NewServer(remoteWriteHandler)
		t.Cleanup(remoteServer.Close)

		testServer := httptest.NewServer(handlerFunc(logger, remoteServer.URL, nil, nil, nil))
		t.Cleanup(testServer.Close)

		data, err := json.Marshal(writeRequestFixture)
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodPost, testServer.URL, bytes.NewBuffer(data))
		require.NoError(t, err)

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)

		require.Equal(t, http.StatusNoContent, resp.StatusCode)

		i := 0
		j := 0
		for _, ts := range writeRequestFixture.Timeseries {
			labels := labelProtosToLabels(ts.Labels)
			for _, s := range ts.Samples {
				require.Equal(t, mockSample{labels, s.Timestamp, s.Value}, appendable.samples[i])
				i++
			}

			for _, e := range ts.Exemplars {
				exemplarLabels := labelProtosToLabels(e.Labels)
				require.Equal(t, mockExemplar{labels, exemplarLabels, e.Timestamp, e.Value}, appendable.exemplars[j])
				j++
			}
		}
	})

	t.Run("invalid json", func(t *testing.T) {
		handler := handlerFunc(log.NewNopLogger(), "http://localhost", nil, nil, nil)

		invalidJSON := `{"timeseries": {}}` // should be an array of timeseries, not an object
		req, err := http.NewRequest("", "", strings.NewReader(invalidJSON))
		require.NoError(t, err)

		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)

		resp := recorder.Result()
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("transport error", func(t *testing.T) {
		rt := httpRoundtripperFunc(func(req *http.Request) (*http.Response, error) {
			return nil, fmt.Errorf("can't dial or whatever")
		})
		handler := handlerFunc(log.NewNopLogger(), "http://localhost", rt, nil, nil)

		req, err := http.NewRequest("", "", strings.NewReader(`{}`))
		require.NoError(t, err)

		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)

		resp := recorder.Result()
		require.Equal(t, http.StatusBadGateway, resp.StatusCode)
	})

	t.Run("basic auth", func(t *testing.T) {
		logger := log.NewNopLogger()

		const (
			username = "user"
			password = "pass"
		)

		remoteServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			u, p, auth := req.BasicAuth()
			assert.True(t, auth)
			assert.Equal(t, username, u)
			assert.Equal(t, password, p)

			rw.WriteHeader(http.StatusUnauthorized)
		}))
		t.Cleanup(remoteServer.Close)

		testServer := httptest.NewServer(handlerFunc(logger, remoteServer.URL, nil, nil, nil))
		t.Cleanup(testServer.Close)

		data, err := json.Marshal(writeRequestFixture)
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodPost, testServer.URL, bytes.NewBuffer(data))
		req.SetBasicAuth(username, password)
		require.NoError(t, err)

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)

		require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("forwarded header", func(t *testing.T) {
		logger := log.NewNopLogger()

		const (
			orgIDHeader = "X-Scope-OrgID"
			orgID       = "42"
		)

		remoteServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			assert.Equal(t, orgID, req.Header.Get(orgIDHeader))
			rw.WriteHeader(http.StatusUnauthorized)
		}))
		t.Cleanup(remoteServer.Close)

		testServer := httptest.NewServer(handlerFunc(logger, remoteServer.URL, nil, []string{orgIDHeader}, []string{orgIDHeader}))
		t.Cleanup(testServer.Close)

		data, err := json.Marshal(writeRequestFixture)
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodPost, testServer.URL, bytes.NewBuffer(data))
		req.Header.Set(orgIDHeader, orgID)
		require.NoError(t, err)

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)

		require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}

// labelProtosToLabels was copied from https://github.com/prometheus/prometheus/blob/57f4ab27/storage/remote/codec.go#L484-L494
func labelProtosToLabels(labelPairs []prompb.Label) labels.Labels {
	result := make(labels.Labels, 0, len(labelPairs))
	for _, l := range labelPairs {
		result = append(result, labels.Label{
			Name:  l.Name,
			Value: l.Value,
		})
	}
	sort.Sort(result)
	return result
}

// mockAppendable and dependencies were copied from https://github.com/prometheus/prometheus/blob/ceaa77f1/storage/remote/write_handler_test.go#L137-L188
type mockAppendable struct {
	latestSample   int64
	samples        []mockSample
	latestExemplar int64
	exemplars      []mockExemplar
	commitErr      error
}

type mockSample struct {
	l labels.Labels
	t int64
	v float64
}

type mockExemplar struct {
	l  labels.Labels
	el labels.Labels
	t  int64
	v  float64
}

func (m *mockAppendable) Appender(_ context.Context) storage.Appender {
	return m
}

func (m *mockAppendable) Append(_ storage.SeriesRef, l labels.Labels, t int64, v float64) (storage.SeriesRef, error) {
	if t < m.latestSample {
		return 0, storage.ErrOutOfOrderSample
	}

	m.latestSample = t
	m.samples = append(m.samples, mockSample{l, t, v})
	return 0, nil
}

func (m *mockAppendable) Commit() error {
	return m.commitErr
}

func (*mockAppendable) Rollback() error {
	return fmt.Errorf("not implemented")
}

func (m *mockAppendable) AppendExemplar(_ storage.SeriesRef, l labels.Labels, e exemplar.Exemplar) (storage.SeriesRef, error) {
	if e.Ts < m.latestExemplar {
		return 0, storage.ErrOutOfOrderExemplar
	}

	m.latestExemplar = e.Ts
	m.exemplars = append(m.exemplars, mockExemplar{l, e.Labels, e.Ts, e.Value})
	return 0, nil
}

type httpRoundtripperFunc func(req *http.Request) (*http.Response, error)

func (f httpRoundtripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
