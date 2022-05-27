package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/gogo/protobuf/proto"
	"github.com/golang/snappy"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/route"
	"github.com/prometheus/prometheus/prompb"
)

var (
	requestCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "prometheus_json_rw_proxy_http_requests_total",
			Help: "Counter of HTTP requests.",
		},
		[]string{"handler", "code"},
	)
	requestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "prometheus_json_rw_proxy_http_request_duration_seconds",
			Help:    "Histogram of latencies for HTTP requests.",
			Buckets: []float64{.1, .2, .4, 1, 3, 8, 20, 60, 120},
		},
		[]string{"handler"},
	)
	responseSize = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "prometheus_json_rw_proxy_http_response_size_bytes",
			Help:    "Histogram of response size for HTTP requests.",
			Buckets: prometheus.ExponentialBuckets(100, 10, 8),
		},
		[]string{"handler"},
	)
)

func main() {
	var (
		listenAddress      string
		path               string
		remoteWriteAddress string
		logHeadersList     string
		forwardHeadersList string
	)
	flag.StringVar(&listenAddress, "listen-address", "0.0.0.0:9091", "Listen address of the server.")
	flag.StringVar(&path, "path", "/write", "Path where write requests will be received.")
	flag.StringVar(&remoteWriteAddress, "remote-write-address", "", "Address where remote writes should be sent.")
	flag.StringVar(&logHeadersList, "log-headers", "", "Comma-separated of headers to log (useful for Mimir's X-Org-ScopeID header)")
	flag.StringVar(&forwardHeadersList, "forward-headers", "", "Comma-separated list of headers to forward (useful for Mimir's X-Org-ScopeID header)")
	flag.Parse()

	logger := log.NewLogfmtLogger(log.NewSyncWriter(os.Stdout))

	if remoteWriteAddress == "" {
		level.Error(logger).Log("msg", "should specify a remote-write-address, but was empty")
		os.Exit(1)
	} else if _, err := url.Parse(remoteWriteAddress); err != nil {
		level.Error(logger).Log("msg", "should specify a valid remote-write-address", "err", err)
		os.Exit(1)
	}

	logHeaders := commaSeparatedNonEmptyStrings(logHeadersList)
	forwardHeaders := commaSeparatedNonEmptyStrings(forwardHeadersList)

	mux := route.New().WithInstrumentation(func(handlerName string, handler http.HandlerFunc) http.HandlerFunc {
		return promhttp.InstrumentHandlerCounter(
			requestCounter.MustCurryWith(prometheus.Labels{"handler": handlerName}),
			promhttp.InstrumentHandlerDuration(
				requestDuration.MustCurryWith(prometheus.Labels{"handler": handlerName}),
				promhttp.InstrumentHandlerResponseSize(
					responseSize.MustCurryWith(prometheus.Labels{"handler": handlerName}),
					handler,
				),
			),
		)
	})
	mux.Post(path, handlerFunc(logger, remoteWriteAddress, http.DefaultTransport, logHeaders, forwardHeaders))
	mux.Get("/metrics", promhttp.Handler().ServeHTTP)

	level.Info(logger).Log("msg", "Starting server", "listen_address", listenAddress, "path", path, "remote_write_address", remoteWriteAddress)
	err := http.ListenAndServe(listenAddress, mux)
	if err != http.ErrServerClosed {
		level.Warn(logger).Log("msg", "can't listen", "err", err)
	}
}

func handlerFunc(logger log.Logger, remoteWriteAddress string, transport http.RoundTripper, logHeaders, forwardHeaders []string) http.HandlerFunc {
	if transport == nil {
		transport = http.DefaultTransport
	}

	return func(rw http.ResponseWriter, req *http.Request) {
		username, password, basicAuth := req.BasicAuth()
		kvs := []interface{}{"remote_addr", req.RemoteAddr, "basic_auth", basicAuth}
		if basicAuth {
			kvs = append(kvs, "basic_user", username)
		}
		for _, h := range logHeaders {
			kvs = append(kvs, h, req.Header.Get(h))
		}
		logger := log.With(logger, kvs...)

		var writeRequest *prompb.WriteRequest
		decoder := json.NewDecoder(req.Body)
		defer req.Body.Close()

		if err := decoder.Decode(&writeRequest); err != nil {
			level.Warn(logger).Log("msg", "invalid request", "err", err)
			http.Error(rw, fmt.Sprintf("invalid request: %s", err), http.StatusBadRequest)
			return
		}

		level.Debug(logger).Log("msg", "received request with", "timeseries", len(writeRequest.Timeseries))

		pBuf := pBufPool.Get().(*proto.Buffer)
		pBuf.Reset()
		defer pBufPool.Put(pBuf)

		err := pBuf.Marshal(writeRequest)
		if err != nil {
			level.Error(logger).Log("msg", "can't marshal outgoing proto", "err", err)
			http.Error(rw, "can't marshal outgoing proto", http.StatusInternalServerError)
			return
		}

		buf := bufPool.Get().([]byte)
		// snappy uses len() to see if it needs to allocate a new slice. Make the
		// buffer as long as possible.
		if buf != nil {
			buf = buf[0:cap(buf)]
		}
		compressed := snappy.Encode(buf, pBuf.Bytes())
		defer bufPool.Put(compressed) //nolint:staticcheck

		outreq, err := http.NewRequest(http.MethodPost, remoteWriteAddress, bytes.NewReader(compressed))
		if err != nil {
			level.Error(logger).Log("msg", "can't build outgoing request", "err", err)
			http.Error(rw, "can't build outgoing request", http.StatusInternalServerError)
			return
		}
		for _, h := range forwardHeaders {
			outreq.Header.Set(h, req.Header.Get(h))
		}

		if basicAuth {
			outreq.SetBasicAuth(username, password)
		}

		resp, err := transport.RoundTrip(outreq)
		if err != nil {
			level.Error(logger).Log("msg", "can't forward request", "err", err)
			http.Error(rw, "can't forward request", http.StatusBadGateway)
			return
		}

		lvl := level.Info
		if resp.StatusCode%100 > 3 {
			lvl = level.Warn
		}
		lvl(logger).Log("msg", "forwarded request", "status", resp.Status)

		rw.WriteHeader(resp.StatusCode)
		io.Copy(rw, resp.Body)
	}
}

var pBufPool = sync.Pool{New: func() interface{} { return proto.NewBuffer(nil) }}
var bufPool = sync.Pool{New: func() interface{} { return []byte(nil) }}

func commaSeparatedNonEmptyStrings(s string) []string {
	if len(s) == 0 {
		return nil
	}
	return strings.Split(s, ",")
}
