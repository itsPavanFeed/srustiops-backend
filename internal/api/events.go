package api

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/itsPavanFeed/srustiops-backend/internal/spec"
	"github.com/itsPavanFeed/srustiops-backend/internal/store"
)

// Event tracking. A tenant admin creates an event source for a connection
// and points the cloud's event router at it: an EventBridge rule on
// CloudTrail management events with an API destination, a Pub/Sub push
// subscription on an audit-log sink, or an Event Grid subscription. Events
// arrive through central, carry the source's secret token, and are matched
// to the managing stack through the inventory. Changes made by the
// platform's own deploy identities are recorded but ignored; any other
// change flags the stack and notifies its business unit. Nothing is changed
// automatically: a person runs a drift check and chooses live -> code or
// code -> live.

const eventNotifyWindow = 10 * time.Minute

type liveEvent struct {
	Action    string // create | update | delete
	Name      string
	Resources []string
	Actor     string
	Time      *time.Time
}

var awsReadOnlyRe = regexp.MustCompile(`^(Get|List|Describe|Head|Lookup|Search|BatchGet|Check|Validate)`)

func hashToken(t string) []byte { h := sha256.Sum256([]byte(t)); return h[:] }

func newEventToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return "pve_" + base64.RawURLEncoding.EncodeToString(b)
}

func parseTime(s string) *time.Time {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return &t
	}
	return nil
}

// parseAWS reads an EventBridge event for a CloudTrail API call (one event
// per delivery) or an array of them.
func parseAWS(body []byte) ([]liveEvent, error) {
	type ev struct {
		Time       string   `json:"time"`
		Resources  []string `json:"resources"`
		DetailType string   `json:"detail-type"`
		Detail     struct {
			EventName    string `json:"eventName"`
			EventSource  string `json:"eventSource"`
			ReadOnly     *bool  `json:"readOnly"`
			ErrorCode    string `json:"errorCode"`
			UserIdentity struct {
				ARN string `json:"arn"`
			} `json:"userIdentity"`
			RequestParameters map[string]any `json:"requestParameters"`
			Resources         []struct {
				ARN string `json:"ARN"`
			} `json:"resources"`
		} `json:"detail"`
	}
	var list []ev
	if strings.HasPrefix(strings.TrimSpace(string(body)), "[") {
		if err := json.Unmarshal(body, &list); err != nil {
			return nil, err
		}
	} else {
		var one ev
		if err := json.Unmarshal(body, &one); err != nil {
			return nil, err
		}
		list = []ev{one}
	}
	var out []liveEvent
	for _, e := range list {
		d := e.Detail
		if d.EventName == "" || d.ErrorCode != "" || (d.ReadOnly != nil && *d.ReadOnly) || awsReadOnlyRe.MatchString(d.EventName) {
			continue
		}
		le := liveEvent{Name: d.EventSource + ":" + d.EventName, Actor: d.UserIdentity.ARN, Time: parseTime(e.Time), Action: "update"}
		switch {
		case strings.HasPrefix(d.EventName, "Create") || strings.HasPrefix(d.EventName, "Run"):
			le.Action = "create"
		case strings.HasPrefix(d.EventName, "Delete") || strings.HasPrefix(d.EventName, "Terminate"):
			le.Action = "delete"
		}
		seen := map[string]bool{}
		add := func(id string) {
			if id != "" && !seen[id] {
				seen[id] = true
				le.Resources = append(le.Resources, id)
			}
		}
		for _, r := range e.Resources {
			add(r)
		}
		for _, r := range d.Resources {
			add(r.ARN)
		}
		if b, ok := d.RequestParameters["bucketName"].(string); ok {
			add("arn:aws:s3:::" + b)
		}
		if len(le.Resources) > 0 {
			out = append(out, le)
		}
	}
	return out, nil
}

// parseGCP reads a Pub/Sub push delivery of an audit LogEntry.
func parseGCP(body []byte) ([]liveEvent, error) {
	var push struct {
		Message struct {
			Data        []byte `json:"data"`
			PublishTime string `json:"publishTime"`
		} `json:"message"`
	}
	if err := json.Unmarshal(body, &push); err != nil || len(push.Message.Data) == 0 {
		return nil, errors.New("not a Pub/Sub push message")
	}
	var entry struct {
		Timestamp    string `json:"timestamp"`
		ProtoPayload struct {
			ServiceName        string `json:"serviceName"`
			MethodName         string `json:"methodName"`
			ResourceName       string `json:"resourceName"`
			AuthenticationInfo struct {
				PrincipalEmail string `json:"principalEmail"`
			} `json:"authenticationInfo"`
			Status *struct {
				Code int `json:"code"`
			} `json:"status"`
		} `json:"protoPayload"`
	}
	if err := json.Unmarshal(push.Message.Data, &entry); err != nil {
		return nil, fmt.Errorf("the message is not an audit log entry: %w", err)
	}
	p := entry.ProtoPayload
	m := strings.ToLower(p.MethodName)
	if p.ResourceName == "" || (p.Status != nil && p.Status.Code != 0) || strings.Contains(m, ".get") || strings.Contains(m, ".list") || strings.HasSuffix(m, "get") || strings.HasSuffix(m, "list") {
		return nil, nil
	}
	le := liveEvent{Name: p.MethodName, Actor: p.AuthenticationInfo.PrincipalEmail, Time: parseTime(entry.Timestamp), Action: "update",
		Resources: []string{"//" + p.ServiceName + "/" + p.ResourceName}}
	switch {
	case strings.Contains(m, "create") || strings.Contains(m, "insert"):
		le.Action = "create"
	case strings.Contains(m, "delete"):
		le.Action = "delete"
	}
	return []liveEvent{le}, nil
}

// parseAzure reads Event Grid events (Event Grid schema). The subscription
// validation handshake is answered with its code.
func parseAzure(body []byte) ([]liveEvent, any, error) {
	var evs []struct {
		EventType string `json:"eventType"`
		Subject   string `json:"subject"`
		EventTime string `json:"eventTime"`
		Data      struct {
			ValidationCode string            `json:"validationCode"`
			ResourceURI    string            `json:"resourceUri"`
			OperationName  string            `json:"operationName"`
			Claims         map[string]string `json:"claims"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &evs); err != nil {
		return nil, nil, err
	}
	var out []liveEvent
	for _, e := range evs {
		switch e.EventType {
		case "Microsoft.EventGrid.SubscriptionValidationEvent":
			return nil, map[string]string{"validationResponse": e.Data.ValidationCode}, nil
		case "Microsoft.Resources.ResourceWriteSuccess", "Microsoft.Resources.ResourceDeleteSuccess", "Microsoft.Resources.ResourceActionSuccess":
		default:
			continue
		}
		id := e.Data.ResourceURI
		if id == "" {
			id = e.Subject
		}
		le := liveEvent{Name: e.Data.OperationName, Actor: e.Data.Claims["appid"], Time: parseTime(e.EventTime), Action: "update", Resources: []string{id}}
		if le.Actor == "" {
			le.Actor = e.Data.Claims["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"]
		}
		if e.EventType == "Microsoft.Resources.ResourceDeleteSuccess" {
			le.Action = "delete"
		}
		out = append(out, le)
	}
	return out, nil, nil
}

// platformActor reports whether an event was made by the platform's own
// deploy or plan identity for this connection.
func platformActor(c *spec.Cloud, actor string, extra []string) bool {
	if actor == "" {
		return false
	}
	for _, x := range extra {
		if x != "" && strings.Contains(actor, x) {
			return true
		}
	}
	switch c.Provider {
	case "aws":
		// arn:aws:sts::<account>:assumed-role/<role>/<session>
		role := ""
		if i := strings.Index(actor, ":assumed-role/"); i >= 0 {
			role, _, _ = strings.Cut(actor[i+len(":assumed-role/"):], "/")
		}
		for _, arn := range []string{c.AWS.RoleARN, c.AWS.PlanRoleARN} {
			if arn != "" && role != "" && lastSegment(arn) == role {
				return true
			}
		}
	case "gcp":
		return actor == c.GCP.ServiceAccountEmail || (c.GCP.PlanServiceAccountEmail != "" && actor == c.GCP.PlanServiceAccountEmail)
	case "azure":
		return actor == c.Azure.ClientID || (c.Azure.PlanClientID != "" && actor == c.Azure.PlanClientID)
	}
	return false
}

func lastSegment(s string) string {
	if i := strings.LastIndex(s, "/"); i >= 0 {
		return s[i+1:]
	}
	return s
}

// cloudEventHook ingests one delivery relayed by central.
func (s *Server) cloudEventHook(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	src, err := s.store.GetEventSource(ctx, r.PathValue("source"))
	tok := r.Header.Get("X-SrustiOps-Event-Token")
	if err != nil || tok == "" || subtle.ConstantTimeCompare(hashToken(tok), src.TokenHash) != 1 {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20+1))
	if err != nil || len(body) > 1<<20 {
		writeErr(w, http.StatusRequestEntityTooLarge, "payload too large")
		return
	}
	conn, err := s.store.GetConnection(ctx, src.ConnectionID)
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	cl, err := spec.DecodeCloud(conn.Cloud)
	if err != nil {
		writeErr(w, 422, err.Error())
		return
	}
	var evs []liveEvent
	switch cl.Provider {
	case "aws":
		evs, err = parseAWS(body)
	case "gcp":
		evs, err = parseGCP(body)
	case "azure":
		var handshake any
		evs, handshake, err = parseAzure(body)
		if handshake != nil {
			s.audit(ctx, RelaySubject, "events.validate", "event-source/"+src.Name, "", nil)
			writeJSON(w, 200, handshake)
			return
		}
	default:
		err = errors.New("the connection has no cloud")
	}
	if err != nil {
		writeErr(w, 400, "unrecognised event: "+err.Error())
		return
	}
	s.store.TouchEventSource(ctx, src.ID)
	recorded, flagged := 0, 0
	for _, le := range evs {
		for _, rid := range le.Resources {
			ev := &store.CloudEvent{SourceID: src.ID, ConnectionID: conn.ID, EventTime: le.Time, Action: le.Action, EventName: le.Name, ResourceID: rid, Actor: le.Actor}
			if stack, err := s.store.InventoryStack(ctx, conn.ID, rid); err == nil {
				ev.Stack = stack
				if st, err := s.store.GetStack(ctx, stack); err == nil {
					ev.BU = st.BU
				}
			}
			if platformActor(cl, le.Actor, src.IgnoreActors) {
				ev.Ignored = "made by the platform's own identity"
			}
			saved, err := s.store.RecordEvent(ctx, ev, eventNotifyWindow)
			if err != nil {
				s.log.Error("recording a cloud event", "err", err)
				continue
			}
			recorded++
			if saved.Stack != "" && saved.Ignored == "" {
				flagged++
			}
			if saved.Notified {
				s.notifyEvent(ctx, store.Notification{Kind: "stack.live_change", Severity: "warning", BU: saved.BU,
					Title: "Changed outside the platform: " + saved.Stack,
					Body:  fmt.Sprintf("%s (%s) on %s by %s. Run a drift check, then choose live -> code or code -> live.", saved.EventName, saved.Action, saved.ResourceID, orDash(saved.Actor)),
					Link:  "stacks/" + saved.Stack})
			}
		}
	}
	writeJSON(w, 202, map[string]int{"recorded": recorded, "flagged": flagged})
}

func orDash(s string) string {
	if s == "" {
		return "an unknown identity"
	}
	return s
}

// --- event sources ---------------------------------------------------------

func (s *Server) eventSetup(src *store.EventSource, conn *store.Connection) map[string]any {
	path := "/webhooks/cloud/" + s.cfg.Tenant + "/" + src.ID
	cl, _ := spec.DecodeCloud(conn.Cloud)
	steps := []string{}
	switch cl.Provider {
	case "aws":
		steps = []string{
			"Create an EventBridge connection with API key authorization: header X-SrustiOps-Event-Token, value = the token.",
			"Create an API destination for <central URL>" + path + " (POST) using that connection.",
			`Create a rule on the default bus with the pattern {"detail-type": ["AWS API Call via CloudTrail"], "detail": {"readOnly": [false]}} and the API destination as its target (CloudTrail must record management events).`,
			"For an organization, send events from each account's bus to a central bus and add the rule there.",
		}
	case "gcp":
		steps = []string{
			"Create a Pub/Sub topic and a log sink in project " + cl.GCP.ProjectID + ` (or at the folder/organization) with the filter logName:"cloudaudit.googleapis.com%2Factivity"`,
			"Grant the sink's writer identity roles/pubsub.publisher on the topic.",
			"Create a push subscription with the endpoint <central URL>" + path + "?token=<token>.",
		}
	case "azure":
		steps = []string{
			"In the subscription, create an Event Grid system topic for Azure subscription events (or use the subscription's events blade).",
			"Add an event subscription of type Web Hook with the Event Grid schema, endpoint <central URL>" + path + "?token=<token>, and the event types ResourceWriteSuccess, ResourceDeleteSuccess and ResourceActionSuccess.",
			"The validation handshake is answered automatically.",
		}
	}
	return map[string]any{"path": path, "steps": steps,
		"ignored": "changes made by this connection's deploy and plan identities are recorded but do not flag stacks"}
}

func (s *Server) listEventSources(w http.ResponseWriter, r *http.Request) {
	srcs, err := s.store.ListEventSources(r.Context())
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	out := []map[string]any{}
	for _, x := range srcs {
		conn, err := s.store.GetConnection(r.Context(), x.ConnectionID)
		if err != nil {
			continue
		}
		out = append(out, map[string]any{"source": x, "setup": s.eventSetup(x, conn)})
	}
	writeJSON(w, 200, out)
}

func (s *Server) createEventSource(w http.ResponseWriter, r *http.Request) {
	if !tenantAdmin(w, r) {
		return
	}
	var b struct {
		Name         string   `json:"name"`
		Connection   string   `json:"connection"`
		IgnoreActors []string `json:"ignore_actors"`
	}
	if !decode(w, r, &b) {
		return
	}
	if !connNameRe.MatchString(b.Name) {
		writeErr(w, 422, "name must be lowercase letters, digits and dashes (2-48)")
		return
	}
	conn, err := s.store.GetConnection(r.Context(), b.Connection)
	if err != nil {
		writeErr(w, 422, "unknown cloud connection "+b.Connection)
		return
	}
	if b.IgnoreActors == nil {
		b.IgnoreActors = []string{}
	}
	tok := newEventToken()
	src, err := s.store.CreateEventSource(r.Context(), &store.EventSource{Name: b.Name, ConnectionID: conn.ID, TokenHash: hashToken(tok), IgnoreActors: b.IgnoreActors, CreatedBy: user(r).Subject})
	if err != nil {
		s.writeStoreErr(w, err, "an event source with that name exists")
		return
	}
	s.audit(r.Context(), user(r).Actor(), "events.source.create", "event-source/"+src.Name, "", map[string]any{"connection": conn.Name})
	// The token is shown once; only its hash is kept.
	writeJSON(w, 201, map[string]any{"source": src, "token": tok, "setup": s.eventSetup(src, conn)})
}

func (s *Server) deleteEventSource(w http.ResponseWriter, r *http.Request) {
	if !tenantAdmin(w, r) {
		return
	}
	src, err := s.store.GetEventSource(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	if s.dryRun(w, r) {
		return
	}
	if err := s.store.DeleteEventSource(r.Context(), src.ID); err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	s.audit(r.Context(), user(r).Actor(), "events.source.delete", "event-source/"+src.Name, "", nil)
	w.WriteHeader(http.StatusNoContent)
}

// listCloudEvents: everything for full control; otherwise only events of
// stacks in the caller's business units.
func (s *Server) listCloudEvents(w http.ResponseWriter, r *http.Request) {
	p := user(r)
	q := r.URL.Query()
	f := store.EventFilter{Stack: q.Get("stack"), Flagged: q.Get("flagged") == "1", Limit: limit(r, 100, 500)}
	if !p.ManagesTenant() {
		f.BUs = p.VisibleBUs()
		if f.BUs == nil {
			f.BUs = []string{}
		}
	}
	if c := q.Get("connection"); c != "" {
		conn, err := s.store.GetConnection(r.Context(), c)
		if err != nil {
			writeErr(w, 404, "unknown connection "+c)
			return
		}
		f.Connection = conn.ID
	}
	evs, err := s.store.ListEvents(r.Context(), f)
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	writeJSON(w, 200, evs)
}

// stackLiveChanges lists changes made outside the platform since the stack's
// last run started (the banner on the stack page).
func (s *Server) stackLiveChanges(w http.ResponseWriter, r *http.Request) {
	st := s.visibleStack(w, r)
	if st == nil {
		return
	}
	f := store.EventFilter{Stack: st.Name, Flagged: true, Limit: 50}
	if st.LastRun != nil {
		f.Since = &st.LastRun.CreatedAt
	}
	evs, err := s.store.ListEvents(r.Context(), f)
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	writeJSON(w, 200, map[string]any{"changes": evs, "since": f.Since})
}
