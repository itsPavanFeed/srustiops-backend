package cloudapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// CostLine is what one BU and stack (from the srustiops-bu and
// srustiops-stack tags or labels) cost in a month. Untagged spend has an
// empty BU and stack.
type CostLine struct {
	Month    string  `json:"month"` // YYYY-MM
	BU       string  `json:"bu"`
	Stack    string  `json:"stack"`
	Amount   float64 `json:"amount"`
	Currency string  `json:"currency"`
}

// monthRange is [first day of month, first day of next month) for each
// month from `from` to `to`, as YYYY-MM-DD.
func monthRange(from, to time.Time) (string, string) {
	a := time.Date(from.Year(), from.Month(), 1, 0, 0, 0, 0, time.UTC)
	b := time.Date(to.Year(), to.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, 1, 0)
	return a.Format("2006-01-02"), b.Format("2006-01-02")
}

// AWSCost reads actual cost from Cost Explorer, grouped by the two tags.
// The tags must be activated as cost allocation tags in the payer account's
// Billing console; until then all spend shows as untagged.
func (c *Client) AWSCost(ctx context.Context, roleARN string, from, to time.Time) ([]CostLine, error) {
	ctx, cancel := ctxTimeout(ctx)
	defer cancel()
	cr, err := c.awsAssume(ctx, roleARN, "srustiops-cost")
	if err != nil {
		return nil, err
	}
	start, end := monthRange(from, to)
	var out []CostLine
	next := ""
	for page := 0; page < maxPages; page++ {
		body := map[string]any{"TimePeriod": map[string]string{"Start": start, "End": end}, "Granularity": "MONTHLY", "Metrics": []string{"UnblendedCost"},
			"GroupBy": []map[string]string{{"Type": "TAG", "Key": "srustiops-bu"}, {"Type": "TAG", "Key": "srustiops-stack"}}}
		if next != "" {
			body["NextPageToken"] = next
		}
		var resp struct {
			ResultsByTime []struct {
				TimePeriod struct{ Start string } `json:"TimePeriod"`
				Groups     []struct {
					Keys    []string `json:"Keys"`
					Metrics map[string]struct {
						Amount string `json:"Amount"`
						Unit   string `json:"Unit"`
					} `json:"Metrics"`
				} `json:"Groups"`
			} `json:"ResultsByTime"`
			NextPageToken string `json:"NextPageToken"`
		}
		if err := c.awsCall(ctx, cr, "us-east-1", "ce", "https://ce.us-east-1.amazonaws.com/", "AWSInsightsIndexService.GetCostAndUsage", body, &resp); err != nil {
			return nil, fmt.Errorf("reading Cost Explorer: %w", err)
		}
		for _, r := range resp.ResultsByTime {
			for _, g := range r.Groups {
				m := g.Metrics["UnblendedCost"]
				amt, _ := strconv.ParseFloat(m.Amount, 64)
				l := CostLine{Month: r.TimePeriod.Start[:7], Amount: amt, Currency: m.Unit}
				// Keys look like "srustiops-bu$payments" ("srustiops-bu$" when untagged).
				for _, k := range g.Keys {
					tag, val, _ := strings.Cut(k, "$")
					switch tag {
					case "srustiops-bu":
						l.BU = val
					case "srustiops-stack":
						l.Stack = val
					}
				}
				out = append(out, l)
			}
		}
		if next = resp.NextPageToken; next == "" {
			break
		}
	}
	return out, nil
}

// AzureCost reads actual cost from Cost Management, grouped by the
// srustiops-stack tag (a Cost Management query groups by one tag key); the
// stack's BU comes from the workspace.
func (c *Client) AzureCost(ctx context.Context, tenantID, clientID, subscription string, from, to time.Time) ([]CostLine, error) {
	ctx, cancel := ctxTimeout(ctx)
	defer cancel()
	tok, err := c.azureToken(ctx, tenantID, clientID)
	if err != nil {
		return nil, err
	}
	start, end := monthRange(from, to)
	endT, _ := time.Parse("2006-01-02", end)
	body, _ := json.Marshal(map[string]any{
		"type": "ActualCost", "timeframe": "Custom",
		"timePeriod": map[string]string{"from": start + "T00:00:00Z", "to": endT.Add(-time.Second).Format(time.RFC3339)},
		"dataset": map[string]any{"granularity": "Monthly",
			"aggregation": map[string]any{"totalCost": map[string]string{"name": "Cost", "function": "Sum"}},
			"grouping":    []map[string]string{{"type": "TagKey", "name": "srustiops-stack"}}},
	})
	u := "https://management.azure.com/subscriptions/" + url.PathEscape(subscription) + "/providers/Microsoft.CostManagement/query?api-version=2023-03-01"
	var out []CostLine
	for page := 0; page < maxPages && u != ""; page++ {
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+tok)
		var resp struct {
			Properties struct {
				NextLink string `json:"nextLink"`
				Columns  []struct {
					Name string `json:"name"`
				} `json:"columns"`
				Rows [][]any `json:"rows"`
			} `json:"properties"`
		}
		if _, err := c.do(req, &resp); err != nil {
			return nil, fmt.Errorf("reading Cost Management: %w", err)
		}
		col := map[string]int{}
		for i, cl := range resp.Properties.Columns {
			col[strings.ToLower(cl.Name)] = i
		}
		for _, row := range resp.Properties.Rows {
			get := func(n string) any {
				if i, ok := col[n]; ok && i < len(row) {
					return row[i]
				}
				return nil
			}
			l := CostLine{Month: start[:7]}
			if s, ok := get("currency").(string); ok {
				l.Currency = s
			}
			if f, ok := get("cost").(float64); ok {
				l.Amount = f
			}
			if m, ok := get("billingmonth").(string); ok && len(m) >= 7 {
				l.Month = m[:7]
			}
			if k, _ := get("tagkey").(string); k == "srustiops-stack" {
				l.Stack, _ = get("tagvalue").(string)
			}
			out = append(out, l)
		}
		u = resp.Properties.NextLink
	}
	return out, nil
}

var bqTableRe = regexp.MustCompile(`^[a-z][a-z0-9-]{4,61}[a-z0-9]\.[A-Za-z0-9_]+\.[A-Za-z0-9_]+$`)

// GCPCost reads actual cost from the Cloud Billing export to BigQuery
// (table = project.dataset.table), grouped by the two labels; GCP has no
// other API for actual cost by label.
func (c *Client) GCPCost(ctx context.Context, provider, serviceAccount, project, table string, from, to time.Time) ([]CostLine, error) {
	if !bqTableRe.MatchString(table) {
		return nil, errors.New("the billing export table must be project.dataset.table")
	}
	ctx, cancel := ctxTimeout(ctx)
	defer cancel()
	tok, err := c.gcpToken(ctx, provider, serviceAccount)
	if err != nil {
		return nil, err
	}
	start, end := monthRange(from, to)
	q := "SELECT invoice.month AS month, " +
		"(SELECT value FROM UNNEST(labels) WHERE key = 'srustiops-bu') AS bu, " +
		"(SELECT value FROM UNNEST(labels) WHERE key = 'srustiops-stack') AS stack, " +
		"SUM(cost) + SUM(IFNULL((SELECT SUM(c.amount) FROM UNNEST(credits) c), 0)) AS amount, ANY_VALUE(currency) AS currency " +
		"FROM `" + table + "` WHERE usage_start_time >= TIMESTAMP(@start) AND usage_start_time < TIMESTAMP(@end) AND project.id = @project GROUP BY 1, 2, 3"
	body, _ := json.Marshal(map[string]any{"query": q, "useLegacySql": false, "timeoutMs": 60000, "parameterMode": "NAMED",
		"queryParameters": []map[string]any{
			{"name": "start", "parameterType": map[string]string{"type": "STRING"}, "parameterValue": map[string]string{"value": start}},
			{"name": "end", "parameterType": map[string]string{"type": "STRING"}, "parameterValue": map[string]string{"value": end}},
			{"name": "project", "parameterType": map[string]string{"type": "STRING"}, "parameterValue": map[string]string{"value": project}},
		}})
	billProject, _, _ := strings.Cut(table, ".")
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://bigquery.googleapis.com/bigquery/v2/projects/"+url.PathEscape(billProject)+"/queries", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	var resp struct {
		JobComplete bool `json:"jobComplete"`
		Rows        []struct {
			F []struct {
				V *string `json:"v"`
			} `json:"f"`
		} `json:"rows"`
	}
	if _, err := c.do(req, &resp); err != nil {
		return nil, fmt.Errorf("querying the billing export: %w", err)
	}
	if !resp.JobComplete {
		return nil, errors.New("the billing export query did not finish within a minute")
	}
	var out []CostLine
	for _, r := range resp.Rows {
		v := func(i int) string {
			if i < len(r.F) && r.F[i].V != nil {
				return *r.F[i].V
			}
			return ""
		}
		amt, _ := strconv.ParseFloat(v(3), 64)
		m := v(0) // invoice month, YYYYMM
		if len(m) == 6 {
			m = m[:4] + "-" + m[4:]
		}
		out = append(out, CostLine{Month: m, BU: v(1), Stack: v(2), Amount: amt, Currency: v(4)})
	}
	return out, nil
}
