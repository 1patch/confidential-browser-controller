package browser

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"
)

type agentControlLease struct {
	id       string
	instance Instance
	timer    *time.Timer
	release  func()
}

// Hold the VM while the application authorizes and performs a Pi tool call.
// Polling requires fresh capabilities; abandoned leases expire automatically.
func (c *Control) agentLease(p Principal) (Instance, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.agents == nil {
		c.agents = map[string]*agentControlLease{}
	}
	if lease := c.agents[p.Owner]; lease != nil {
		if lease.id != p.ID {
			return Instance{}, ErrCapacity
		}
		lease.timer.Reset(time.Until(time.Unix(p.Expires, 0)))
		return lease.instance, nil
	}
	instance, release, err := c.Fleet.Lease(p.Owner)
	if err != nil {
		return Instance{}, err
	}
	lease := &agentControlLease{id: p.ID, instance: instance, release: release}
	lease.timer = time.AfterFunc(time.Until(time.Unix(p.Expires, 0)), func() { c.endAgentLease(p.Owner, p.ID) })
	c.agents[p.Owner] = lease
	return instance, nil
}
func (c *Control) endAgentLease(owner, id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if lease := c.agents[owner]; lease != nil && lease.id == id {
		lease.timer.Stop()
		lease.release()
		delete(c.agents, owner)
	}
}

func (c *Control) serveAgent(w http.ResponseWriter, r *http.Request, p Principal) {
	deny := func() { http.Error(w, `{"error":"agent outcome unavailable or uncertain"}`, 409) }
	var step AgentStep
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxAgentMessage))
	dec.DisallowUnknownFields()
	if dec.Decode(&step) != nil || dec.Decode(new(any)) != io.EOF || step.ID != p.ID {
		http.Error(w, `{"error":"invalid request"}`, 400)
		return
	}
	i, err := c.agentLease(p)
	if err != nil || i.Owner != p.Owner {
		deny()
		return
	}
	connect := c.connect
	if connect == nil {
		connect = VerifiedHTTP
	}
	client, err := connect(i.Domain, i.Repository)
	if err != nil || p.Expires <= time.Now().Unix() {
		deny()
		return
	}
	defer client.CloseIdleConnections()
	p.Audience = i.Name
	token, err := SignCapability(c.WorkerKey, p)
	if err != nil {
		deny()
		return
	}
	body, _ := json.Marshal(step)
	ctx, cancel := context.WithDeadline(r.Context(), time.Unix(p.Expires, 0))
	defer cancel()
	forward, err := http.NewRequestWithContext(ctx, "POST", "https://"+i.Domain+"/v1/agent", bytes.NewReader(body))
	if err != nil {
		deny()
		return
	}
	forward.Header.Set("Authorization", "Bearer "+token)
	forward.Header.Set("Content-Type", "application/json")
	response, err := client.Do(forward)
	if err != nil {
		deny()
		return
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, MaxAgentMessage+1))
	if err != nil || response.StatusCode != 200 || len(data) > MaxAgentMessage {
		deny()
		return
	}
	var event AgentEvent
	if json.Unmarshal(data, &event) != nil || !json.Valid(event.Message) {
		deny()
		return
	}
	var terminal struct {
		Result json.RawMessage `json:"boundResult"`
		Error  string          `json:"error"`
	}
	if json.Unmarshal(event.Message, &terminal) != nil {
		deny()
		return
	}
	if step.Cancel || len(terminal.Result) > 0 || terminal.Error != "" {
		c.endAgentLease(p.Owner, p.ID)
	}
	w.Write(data)
}
