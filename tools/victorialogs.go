package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	mcpgrafana "github.com/grafana/mcp-grafana"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

const (
	// DefaultVictoriaLogsLogLimit is the default number of log lines to return if not specified
	DefaultVictoriaLogsLogLimit = 10

	// MaxVictoriaLogsLogLimit is the maximum number of log lines that can be requested
	MaxVictoriaLogsLogLimit = 100
)

// victoriaLogsFieldResponse represents the response from VictoriaLogs field_names and field_values endpoints
type victoriaLogsFieldResponse struct {
	Values []struct {
		Value string `json:"value"`
		Hits  int64  `json:"hits"`
	} `json:"values"`
}

// victoriaLogsHitsResponse represents the response from VictoriaLogs hits endpoint
type victoriaLogsHitsResponse struct {
	Hits []struct {
		Fields     map[string]string `json:"fields"`
		Timestamps []string          `json:"timestamps"`
		Values     []int64           `json:"values"`
		Total      int64             `json:"total"`
	} `json:"hits"`
}

func newVictoriaLogsClient(ctx context.Context, uid string) (*Client, error) {
	// First check if the datasource exists
	_, err := getDatasourceByUID(ctx, GetDatasourceByUIDParams{UID: uid})
	if err != nil {
		return nil, err
	}

	cfg := mcpgrafana.GrafanaConfigFromContext(ctx)
	proxyURL := fmt.Sprintf("%s/api/datasources/proxy/uid/%s", strings.TrimRight(cfg.URL, "/"), uid)

	// Create custom transport with TLS configuration if available
	transport, err := mcpgrafana.BuildTransport(&cfg, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create custom transport: %w", err)
	}
	transport = NewAuthRoundTripper(transport, cfg.AccessToken, cfg.IDToken, cfg.APIKey, cfg.BasicAuth)
	transport = mcpgrafana.NewOrgIDRoundTripper(transport, cfg.OrgID)

	client := &http.Client{
		Transport: mcpgrafana.NewUserAgentTransport(transport),
	}

	return &Client{
		httpClient: client,
		baseURL:    proxyURL,
	}, nil
}

// --- List Field Names ---

// ListVictoriaLogsFieldNamesParams defines the parameters for listing VictoriaLogs field names
type ListVictoriaLogsFieldNamesParams struct {
	DatasourceUID string `json:"datasourceUid" jsonschema:"required,description=The UID of the VictoriaLogs datasource to query"`
	Query         string `json:"query,omitempty" jsonschema:"description=Optional LogsQL query to scope the field names (e.g. 'app:nginx'). Defaults to '*' (all logs)."`
	StartRFC3339  string `json:"startRfc3339,omitempty" jsonschema:"description=Optionally\\, the start time in RFC3339 format (defaults to 1 hour ago)"`
	EndRFC3339    string `json:"endRfc3339,omitempty" jsonschema:"description=Optionally\\, the end time in RFC3339 format (defaults to now)"`
}

// listVictoriaLogsFieldNames lists all field names in a VictoriaLogs datasource
func listVictoriaLogsFieldNames(ctx context.Context, args ListVictoriaLogsFieldNamesParams) ([]string, error) {
	client, err := newVictoriaLogsClient(ctx, args.DatasourceUID)
	if err != nil {
		return nil, fmt.Errorf("creating VictoriaLogs client: %w", err)
	}

	params := url.Values{}
	query := args.Query
	if query == "" {
		query = "*"
	}
	params.Add("query", query)

	startTime, endTime := getDefaultTimeRange(args.StartRFC3339, args.EndRFC3339)
	params.Add("start", startTime)
	params.Add("end", endTime)

	bodyBytes, err := client.makeRequest(ctx, "GET", "/select/logsql/field_names", params)
	if err != nil {
		return nil, err
	}

	var response victoriaLogsFieldResponse
	if err := json.Unmarshal(bodyBytes, &response); err != nil {
		return nil, fmt.Errorf("unmarshalling response (content: %s): %w", string(bodyBytes), err)
	}

	result := make([]string, len(response.Values))
	for i, v := range response.Values {
		result[i] = v.Value
	}

	return result, nil
}

// ListVictoriaLogsFieldNames is a tool for listing VictoriaLogs field names
var ListVictoriaLogsFieldNames = mcpgrafana.MustTool(
	"list_victorialogs_field_names",
	"Lists all available field names found in logs within a VictoriaLogs datasource and time range. Returns a list of field name strings (e.g., `[\"_msg\", \"host\", \"level\"]`). Optionally scope results using a LogsQL query. Defaults to the last hour if the time range is omitted.",
	listVictoriaLogsFieldNames,
	mcp.WithTitleAnnotation("List VictoriaLogs field names"),
	mcp.WithIdempotentHintAnnotation(true),
	mcp.WithReadOnlyHintAnnotation(true),
)

// --- List Field Values ---

// ListVictoriaLogsFieldValuesParams defines the parameters for listing VictoriaLogs field values
type ListVictoriaLogsFieldValuesParams struct {
	DatasourceUID string `json:"datasourceUid" jsonschema:"required,description=The UID of the VictoriaLogs datasource to query"`
	FieldName     string `json:"fieldName" jsonschema:"required,description=The name of the field to retrieve values for (e.g. 'host'\\, 'level'\\, 'app')"`
	Query         string `json:"query,omitempty" jsonschema:"description=Optional LogsQL query to scope the field values. Defaults to '*' (all logs)."`
	Limit         int    `json:"limit,omitempty" jsonschema:"default=50,description=Maximum number of values to return"`
	StartRFC3339  string `json:"startRfc3339,omitempty" jsonschema:"description=Optionally\\, the start time in RFC3339 format (defaults to 1 hour ago)"`
	EndRFC3339    string `json:"endRfc3339,omitempty" jsonschema:"description=Optionally\\, the end time in RFC3339 format (defaults to now)"`
}

// listVictoriaLogsFieldValues lists all values for a specific field in a VictoriaLogs datasource
func listVictoriaLogsFieldValues(ctx context.Context, args ListVictoriaLogsFieldValuesParams) ([]string, error) {
	client, err := newVictoriaLogsClient(ctx, args.DatasourceUID)
	if err != nil {
		return nil, fmt.Errorf("creating VictoriaLogs client: %w", err)
	}

	params := url.Values{}
	query := args.Query
	if query == "" {
		query = "*"
	}
	params.Add("query", query)
	params.Add("field", args.FieldName)

	startTime, endTime := getDefaultTimeRange(args.StartRFC3339, args.EndRFC3339)
	params.Add("start", startTime)
	params.Add("end", endTime)

	if args.Limit > 0 {
		params.Add("limit", fmt.Sprintf("%d", args.Limit))
	}

	bodyBytes, err := client.makeRequest(ctx, "GET", "/select/logsql/field_values", params)
	if err != nil {
		return nil, err
	}

	var response victoriaLogsFieldResponse
	if err := json.Unmarshal(bodyBytes, &response); err != nil {
		return nil, fmt.Errorf("unmarshalling response (content: %s): %w", string(bodyBytes), err)
	}

	result := make([]string, len(response.Values))
	for i, v := range response.Values {
		result[i] = v.Value
	}

	return result, nil
}

// ListVictoriaLogsFieldValues is a tool for listing VictoriaLogs field values
var ListVictoriaLogsFieldValues = mcpgrafana.MustTool(
	"list_victorialogs_field_values",
	"Retrieves all unique values for a specific field within a VictoriaLogs datasource and time range. Returns a list of string values (e.g., for `fieldName=\"level\"`, might return `[\"info\", \"warn\", \"error\"]`). Useful for discovering filter options. Optionally scope results using a LogsQL query. Defaults to the last hour if the time range is omitted.",
	listVictoriaLogsFieldValues,
	mcp.WithTitleAnnotation("List VictoriaLogs field values"),
	mcp.WithIdempotentHintAnnotation(true),
	mcp.WithReadOnlyHintAnnotation(true),
)

// --- Query Logs ---

// QueryVictoriaLogsParams defines the parameters for querying VictoriaLogs
type QueryVictoriaLogsParams struct {
	DatasourceUID string `json:"datasourceUid" jsonschema:"required,description=The UID of the VictoriaLogs datasource to query"`
	LogsQL        string `json:"logsql" jsonschema:"required,description=The LogsQL query to execute against VictoriaLogs. Supports full LogsQL syntax including field filters\\, text matching\\, and pipeline operations."`
	StartRFC3339  string `json:"startRfc3339,omitempty" jsonschema:"description=Optionally\\, the start time of the query in RFC3339 format"`
	EndRFC3339    string `json:"endRfc3339,omitempty" jsonschema:"description=Optionally\\, the end time of the query in RFC3339 format"`
	Limit         int    `json:"limit,omitempty" jsonschema:"default=10,description=Optionally\\, the maximum number of log entries to return (default max: 100\\, configurable by MCP server)."`
}

// QueryVictoriaLogsResult wraps the VictoriaLogs query result with optional hints
type QueryVictoriaLogsResult struct {
	Data     []LogEntry        `json:"data"`
	Hints    *EmptyResultHints `json:"hints,omitempty"`
	Metadata *QueryMetadata    `json:"metadata,omitempty"`
}

// enforceVictoriaLogsLogLimit ensures a log limit value is within acceptable bounds
func enforceVictoriaLogsLogLimit(ctx context.Context, requestedLimit int) int {
	config := mcpgrafana.GrafanaConfigFromContext(ctx)
	maxLimit := config.MaxVictoriaLogsLogLimit
	if maxLimit <= 0 {
		maxLimit = MaxVictoriaLogsLogLimit
	}

	if requestedLimit <= 0 {
		if DefaultVictoriaLogsLogLimit > maxLimit {
			return maxLimit
		}
		return DefaultVictoriaLogsLogLimit
	}
	if requestedLimit > maxLimit {
		return maxLimit
	}
	return requestedLimit
}

// queryVictoriaLogsLogs queries logs from a VictoriaLogs datasource using LogsQL
func queryVictoriaLogsLogs(ctx context.Context, args QueryVictoriaLogsParams) (*QueryVictoriaLogsResult, error) {
	client, err := newVictoriaLogsClient(ctx, args.DatasourceUID)
	if err != nil {
		return nil, fmt.Errorf("creating VictoriaLogs client: %w", err)
	}

	startTime, endTime := getDefaultTimeRange(args.StartRFC3339, args.EndRFC3339)
	limit := enforceVictoriaLogsLogLimit(ctx, args.Limit)

	// Request one extra to detect truncation
	queryLimit := limit + 1

	params := url.Values{}
	params.Add("query", args.LogsQL)
	params.Add("start", startTime)
	params.Add("end", endTime)
	params.Add("limit", fmt.Sprintf("%d", queryLimit))

	bodyBytes, err := client.makeRequest(ctx, "GET", "/select/logsql/query", params)
	if err != nil {
		return nil, err
	}

	// Parse JSON lines response (one JSON object per line)
	var entries []LogEntry
	lines := bytes.Split(bodyBytes, []byte("\n"))
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		var fields map[string]interface{}
		if err := json.Unmarshal(line, &fields); err != nil {
			continue // Skip malformed lines
		}

		entry := LogEntry{
			Labels: make(map[string]string),
		}

		// Extract standard fields
		if msg, ok := fields["_msg"]; ok {
			entry.Line = fmt.Sprintf("%v", msg)
			delete(fields, "_msg")
		}
		if t, ok := fields["_time"]; ok {
			entry.Timestamp = fmt.Sprintf("%v", t)
			delete(fields, "_time")
		}

		// Put remaining fields into Labels
		for k, v := range fields {
			// Skip empty _stream field
			if k == "_stream" {
				s := fmt.Sprintf("%v", v)
				if s == "" || s == "{}" {
					continue
				}
			}
			entry.Labels[k] = fmt.Sprintf("%v", v)
		}

		entries = append(entries, entry)
	}

	// Ensure entries is not nil
	if entries == nil {
		entries = []LogEntry{}
	}

	// Detect truncation and trim to actual limit
	truncated := len(entries) > limit
	if truncated {
		entries = entries[:limit]
	}

	result := &QueryVictoriaLogsResult{
		Data: entries,
		Metadata: &QueryMetadata{
			LinesReturned:    len(entries),
			MaxLinesAllowed:  limit,
			ResultsTruncated: truncated,
		},
	}

	// Add hints if the result is empty
	if len(entries) == 0 {
		var parsedStart, parsedEnd time.Time
		if startTime != "" {
			parsedStart, _ = time.Parse(time.RFC3339, startTime)
		}
		if endTime != "" {
			parsedEnd, _ = time.Parse(time.RFC3339, endTime)
		}
		result.Hints = GenerateEmptyResultHints(HintContext{
			DatasourceType: "victorialogs",
			Query:          args.LogsQL,
			StartTime:      parsedStart,
			EndTime:        parsedEnd,
		})
	}

	return result, nil
}

// QueryVictoriaLogsLogs is a tool for querying logs from VictoriaLogs
var QueryVictoriaLogsLogs = mcpgrafana.MustTool(
	"query_victorialogs_logs",
	"Executes a LogsQL query against a VictoriaLogs datasource to retrieve log entries. Returns a list of results, each containing a timestamp, log line, and field labels. Defaults to the last hour and a limit of 10 entries. Supports full LogsQL syntax (e.g., `level:error AND _msg:\"connection refused\"`, `app:nginx`). Prefer using `query_victorialogs_stats` first to check log volume and `list_victorialogs_field_names` and `list_victorialogs_field_values` to discover available fields.",
	queryVictoriaLogsLogs,
	mcp.WithTitleAnnotation("Query VictoriaLogs logs"),
	mcp.WithIdempotentHintAnnotation(true),
	mcp.WithReadOnlyHintAnnotation(true),
)

// --- Query Stats (Hits) ---

// VictoriaLogsHitsResult represents hit count statistics from VictoriaLogs
type VictoriaLogsHitsResult struct {
	Hits  []VictoriaLogsHitEntry `json:"hits"`
	Total int64                  `json:"total"`
}

// VictoriaLogsHitEntry represents a single hit stat entry
type VictoriaLogsHitEntry struct {
	Fields map[string]string `json:"fields"`
	Total  int64             `json:"total"`
}

// QueryVictoriaLogsStatsParams defines the parameters for querying VictoriaLogs hit statistics
type QueryVictoriaLogsStatsParams struct {
	DatasourceUID string `json:"datasourceUid" jsonschema:"required,description=The UID of the VictoriaLogs datasource to query"`
	LogsQL        string `json:"logsql" jsonschema:"required,description=The LogsQL query to get hit statistics for"`
	Step          string `json:"step" jsonschema:"required,description=The time bucket size for grouping results (e.g. '5m'\\, '1h'\\, '1d')"`
	StartRFC3339  string `json:"startRfc3339,omitempty" jsonschema:"description=Optionally\\, the start time in RFC3339 format (defaults to 1 hour ago)"`
	EndRFC3339    string `json:"endRfc3339,omitempty" jsonschema:"description=Optionally\\, the end time in RFC3339 format (defaults to now)"`
}

// queryVictoriaLogsStats queries hit statistics from a VictoriaLogs datasource
func queryVictoriaLogsStats(ctx context.Context, args QueryVictoriaLogsStatsParams) (*VictoriaLogsHitsResult, error) {
	client, err := newVictoriaLogsClient(ctx, args.DatasourceUID)
	if err != nil {
		return nil, fmt.Errorf("creating VictoriaLogs client: %w", err)
	}

	startTime, endTime := getDefaultTimeRange(args.StartRFC3339, args.EndRFC3339)

	params := url.Values{}
	params.Add("query", args.LogsQL)
	params.Add("start", startTime)
	params.Add("end", endTime)
	params.Add("step", args.Step)

	bodyBytes, err := client.makeRequest(ctx, "GET", "/select/logsql/hits", params)
	if err != nil {
		return nil, err
	}

	var response victoriaLogsHitsResponse
	if err := json.Unmarshal(bodyBytes, &response); err != nil {
		return nil, fmt.Errorf("unmarshalling response (content: %s): %w", string(bodyBytes), err)
	}

	var totalHits int64
	hits := make([]VictoriaLogsHitEntry, len(response.Hits))
	for i, h := range response.Hits {
		hits[i] = VictoriaLogsHitEntry{
			Fields: h.Fields,
			Total:  h.Total,
		}
		totalHits += h.Total
	}

	return &VictoriaLogsHitsResult{
		Hits:  hits,
		Total: totalHits,
	}, nil
}

// QueryVictoriaLogsStats is a tool for querying hit statistics from VictoriaLogs
var QueryVictoriaLogsStats = mcpgrafana.MustTool(
	"query_victorialogs_stats",
	"Retrieves hit count statistics for logs matching a LogsQL query in a VictoriaLogs datasource, grouped by time buckets. Returns total hit counts. Useful for understanding log volume before running full queries. Defaults to the last hour if the time range is omitted.",
	queryVictoriaLogsStats,
	mcp.WithTitleAnnotation("Get VictoriaLogs hit statistics"),
	mcp.WithIdempotentHintAnnotation(true),
	mcp.WithReadOnlyHintAnnotation(true),
)

// AddVictoriaLogsTools registers all VictoriaLogs tools with the MCP server
func AddVictoriaLogsTools(mcp *server.MCPServer) {
	ListVictoriaLogsFieldNames.Register(mcp)
	ListVictoriaLogsFieldValues.Register(mcp)
	QueryVictoriaLogsLogs.Register(mcp)
	QueryVictoriaLogsStats.Register(mcp)
}
