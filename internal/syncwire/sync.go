// Package syncwire describes scoped replication over MQTT.
package syncwire

import "encoding/json"

type Event struct {
	Seq  int64           `json:"seq"`
	Kind string          `json:"kind"`
	Data json.RawMessage `json:"data"`
}

type Page struct {
	Epoch   string  `json:"epoch"`
	Scope   string  `json:"scope"`
	After   int64   `json:"after"`
	Through int64   `json:"through"`
	More    bool    `json:"more"`
	Reset   bool    `json:"reset,omitempty"`
	Events  []Event `json:"events"`
}
