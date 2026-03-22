package tools

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	mcpgrafana "github.com/grafana/mcp-grafana"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnforceVictoriaLogsLogLimit(t *testing.T) {
	tests := []struct {
		name           string
		maxLokiLimit   int
		requestedLimit int
		expectedLimit  int
	}{
		{
			name:           "default limit when requested is 0",
			maxLokiLimit:   100,
			requestedLimit: 0,
			expectedLimit:  DefaultVictoriaLogsLogLimit,
		},
		{
			name:           "default limit when requested is negative",
			maxLokiLimit:   100,
			requestedLimit: -5,
			expectedLimit:  DefaultVictoriaLogsLogLimit,
		},
		{
			name:           "requested limit within bounds",
			maxLokiLimit:   100,
			requestedLimit: 50,
			expectedLimit:  50,
		},
		{
			name:           "requested limit exceeds max",
			maxLokiLimit:   100,
			requestedLimit: 150,
			expectedLimit:  100,
		},
		{
			name:           "fallback to default max when config is 0",
			maxLokiLimit:   0,
			requestedLimit: 150,
			expectedLimit:  MaxVictoriaLogsLogLimit,
		},
		{
			name:           "default limit capped to maxLimit when maxLimit is lower",
			maxLokiLimit:   5,
			requestedLimit: 0,
			expectedLimit:  5,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := mcpgrafana.GrafanaConfig{
				MaxLokiLogLimit: tc.maxLokiLimit,
			}
			ctx := mcpgrafana.WithGrafanaConfig(context.Background(), cfg)

			result := enforceVictoriaLogsLogLimit(ctx, tc.requestedLimit)
			assert.Equal(t, tc.expectedLimit, result)
		})
	}
}

func TestParseVictoriaLogsJSONLines(t *testing.T) {
	tests := []struct {
		name           string
		responseBody   string
		expectedCount  int
		expectedFirst  LogEntry
		expectedLabels map[string]string
	}{
		{
			name: "single log entry",
			responseBody: `{"_msg":"error occurred","_time":"2024-01-01T12:00:00Z","_stream":"{host=\"host-1\"}","host":"host-1","level":"error"}`,
			expectedCount: 1,
			expectedFirst: LogEntry{
				Timestamp: "2024-01-01T12:00:00Z",
				Line:      "error occurred",
				Labels: map[string]string{
					"_stream": "{host=\"host-1\"}",
					"host":    "host-1",
					"level":   "error",
				},
			},
		},
		{
			name: "multiple log entries",
			responseBody: `{"_msg":"line 1","_time":"2024-01-01T12:00:00Z","app":"nginx"}
{"_msg":"line 2","_time":"2024-01-01T12:00:01Z","app":"nginx"}
{"_msg":"line 3","_time":"2024-01-01T12:00:02Z","app":"nginx"}`,
			expectedCount: 3,
		},
		{
			name:          "empty response",
			responseBody:  "",
			expectedCount: 0,
		},
		{
			name: "empty _stream is excluded",
			responseBody: `{"_msg":"test","_time":"2024-01-01T12:00:00Z","_stream":"{}","level":"info"}`,
			expectedCount: 1,
			expectedFirst: LogEntry{
				Timestamp: "2024-01-01T12:00:00Z",
				Line:      "test",
				Labels: map[string]string{
					"level": "info",
				},
			},
		},
		{
			name: "trailing newline handled",
			responseBody: `{"_msg":"test","_time":"2024-01-01T12:00:00Z","level":"info"}
`,
			expectedCount: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Simulate parsing the JSON lines (same logic as queryVictoriaLogsLogs)
			var entries []LogEntry
			lines := strings.Split(tc.responseBody, "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if len(line) == 0 {
					continue
				}

				var fields map[string]interface{}
				if err := json.Unmarshal([]byte(line), &fields); err != nil {
					continue
				}

				entry := LogEntry{
					Labels: make(map[string]string),
				}

				if msg, ok := fields["_msg"]; ok {
					entry.Line = msg.(string)
					delete(fields, "_msg")
				}
				if ts, ok := fields["_time"]; ok {
					entry.Timestamp = ts.(string)
					delete(fields, "_time")
				}

				for k, v := range fields {
					if k == "_stream" {
						s := v.(string)
						if s == "" || s == "{}" {
							continue
						}
					}
					entry.Labels[k] = v.(string)
				}

				entries = append(entries, entry)
			}

			if entries == nil {
				entries = []LogEntry{}
			}

			assert.Equal(t, tc.expectedCount, len(entries))

			if tc.expectedCount > 0 && tc.expectedFirst.Timestamp != "" {
				assert.Equal(t, tc.expectedFirst.Timestamp, entries[0].Timestamp)
				assert.Equal(t, tc.expectedFirst.Line, entries[0].Line)
				assert.Equal(t, tc.expectedFirst.Labels, entries[0].Labels)
			}
		})
	}
}

func TestParseVictoriaLogsFieldResponse(t *testing.T) {
	tests := []struct {
		name           string
		responseBody   string
		expectedResult []string
	}{
		{
			name:           "multiple fields",
			responseBody:   `{"values":[{"value":"_msg","hits":1000},{"value":"host","hits":500},{"value":"level","hits":300}]}`,
			expectedResult: []string{"_msg", "host", "level"},
		},
		{
			name:           "empty values",
			responseBody:   `{"values":[]}`,
			expectedResult: []string{},
		},
		{
			name:           "single field",
			responseBody:   `{"values":[{"value":"app","hits":42}]}`,
			expectedResult: []string{"app"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var response victoriaLogsFieldResponse
			err := json.Unmarshal([]byte(tc.responseBody), &response)
			require.NoError(t, err)

			result := make([]string, len(response.Values))
			for i, v := range response.Values {
				result[i] = v.Value
			}

			assert.Equal(t, tc.expectedResult, result)
		})
	}
}

func TestParseVictoriaLogsHitsResponse(t *testing.T) {
	tests := []struct {
		name          string
		responseBody  string
		expectedTotal int64
		expectedHits  int
	}{
		{
			name: "single hit group",
			responseBody: `{"hits":[{"fields":{},"timestamps":["2024-01-01T00:00:00Z"],"values":[1000],"total":1000}]}`,
			expectedTotal: 1000,
			expectedHits:  1,
		},
		{
			name: "multiple hit groups",
			responseBody: `{"hits":[{"fields":{"level":"error"},"timestamps":["2024-01-01T00:00:00Z"],"values":[500],"total":500},{"fields":{"level":"info"},"timestamps":["2024-01-01T00:00:00Z"],"values":[1500],"total":1500}]}`,
			expectedTotal: 2000,
			expectedHits:  2,
		},
		{
			name:          "empty hits",
			responseBody:  `{"hits":[]}`,
			expectedTotal: 0,
			expectedHits:  0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var response victoriaLogsHitsResponse
			err := json.Unmarshal([]byte(tc.responseBody), &response)
			require.NoError(t, err)

			var totalHits int64
			hits := make([]VictoriaLogsHitEntry, len(response.Hits))
			for i, h := range response.Hits {
				hits[i] = VictoriaLogsHitEntry{
					Fields: h.Fields,
					Total:  h.Total,
				}
				totalHits += h.Total
			}

			assert.Equal(t, tc.expectedTotal, totalHits)
			assert.Equal(t, tc.expectedHits, len(hits))
		})
	}
}

func TestVictoriaLogsFieldNamesEndToEnd(t *testing.T) {
	// Create a mock VictoriaLogs server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/select/logsql/field_names", r.URL.Path)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"values": []map[string]interface{}{
				{"value": "_msg", "hits": 1000},
				{"value": "host", "hits": 500},
			},
		})
	}))
	defer srv.Close()

	client := &Client{
		httpClient: srv.Client(),
		baseURL:    srv.URL,
	}

	params := url.Values{}
	params.Add("query", "*")
	bodyBytes, err := client.makeRequest(context.Background(), "GET", "/select/logsql/field_names", params)
	require.NoError(t, err)

	var response victoriaLogsFieldResponse
	err = json.Unmarshal(bodyBytes, &response)
	require.NoError(t, err)

	assert.Len(t, response.Values, 2)
	assert.Equal(t, "_msg", response.Values[0].Value)
	assert.Equal(t, "host", response.Values[1].Value)
}

func TestVictoriaLogsQueryEndToEnd(t *testing.T) {
	// Create a mock VictoriaLogs server returning JSON lines
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/select/logsql/query", r.URL.Path)

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"_msg":"error occurred","_time":"2024-01-01T12:00:00Z","_stream":"{}","host":"host-1","level":"error"}
{"_msg":"another error","_time":"2024-01-01T12:00:01Z","_stream":"{}","host":"host-2","level":"warn"}
`))
	}))
	defer srv.Close()

	client := &Client{
		httpClient: srv.Client(),
		baseURL:    srv.URL,
	}

	params := url.Values{}
	params.Add("query", "*")
	bodyBytes, err := client.makeRequest(context.Background(), "GET", "/select/logsql/query", params)
	require.NoError(t, err)

	// Parse JSON lines
	var entries []LogEntry
	lines := strings.Split(string(bodyBytes), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		var fields map[string]interface{}
		if err := json.Unmarshal([]byte(line), &fields); err != nil {
			continue
		}

		entry := LogEntry{
			Labels: make(map[string]string),
		}

		if msg, ok := fields["_msg"]; ok {
			entry.Line = msg.(string)
			delete(fields, "_msg")
		}
		if ts, ok := fields["_time"]; ok {
			entry.Timestamp = ts.(string)
			delete(fields, "_time")
		}

		for k, v := range fields {
			if k == "_stream" {
				s := v.(string)
				if s == "" || s == "{}" {
					continue
				}
			}
			entry.Labels[k] = v.(string)
		}

		entries = append(entries, entry)
	}

	require.Len(t, entries, 2)
	assert.Equal(t, "error occurred", entries[0].Line)
	assert.Equal(t, "2024-01-01T12:00:00Z", entries[0].Timestamp)
	assert.Equal(t, "host-1", entries[0].Labels["host"])
	assert.Equal(t, "error", entries[0].Labels["level"])
	assert.NotContains(t, entries[0].Labels, "_stream") // empty _stream excluded

	assert.Equal(t, "another error", entries[1].Line)
	assert.Equal(t, "host-2", entries[1].Labels["host"])
}

func TestVictoriaLogsHitsEndToEnd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/select/logsql/hits", r.URL.Path)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"hits": []map[string]interface{}{
				{
					"fields":     map[string]string{},
					"timestamps": []string{"2024-01-01T00:00:00Z", "2024-01-01T01:00:00Z"},
					"values":     []int64{500, 300},
					"total":      800,
				},
			},
		})
	}))
	defer srv.Close()

	client := &Client{
		httpClient: srv.Client(),
		baseURL:    srv.URL,
	}

	params := url.Values{}
	params.Add("query", "*")
	params.Add("step", "1h")
	bodyBytes, err := client.makeRequest(context.Background(), "GET", "/select/logsql/hits", params)
	require.NoError(t, err)

	var response victoriaLogsHitsResponse
	err = json.Unmarshal(bodyBytes, &response)
	require.NoError(t, err)

	assert.Len(t, response.Hits, 1)
	assert.Equal(t, int64(800), response.Hits[0].Total)
}
