package githubwebhook

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"io/ioutil"
	"log"
	"net/http"
	"runtime"
	"strings"
)

type EventHandler struct {
	signatureKey []byte
	eventHooks   map[string][]HookFunc
}

type HookFunc func(event, id string, body []byte)

func NewEventHandler(signatureKey []byte) *EventHandler {
	server := &EventHandler{
		signatureKey: signatureKey,
		eventHooks:   make(map[string][]HookFunc),
	}
	return server
}

func (self *EventHandler) Handler() func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		defer handleRecover(w, r)
		if r.Method != "POST" {
			http.Error(w, "Request not found", http.StatusNotFound)
			return
		}
		body, _ := ioutil.ReadAll(r.Body)
		signature := []byte(strings.TrimPrefix(r.Header.Get("X-Hub-Signature"), "sha1="))
		if !self.compareSignatures(body, signature) {
			http.Error(w, "Unauthorized request", http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
		event := r.Header.Get("X-GitHub-Event")
		id := r.Header.Get("X-GitHub-Delivery")
		if events, ok := self.eventHooks[event]; ok {
			for _, hook := range events {
				hook(event, id, body)
			}
		}
	}
}

func (self *EventHandler) AddHook(event string, hook HookFunc) {
	events, ok := self.eventHooks[event]
	if !ok {
		events = make([]HookFunc, 0)
	}
	self.eventHooks[event] = append(events, hook)
}

func handleRecover(w http.ResponseWriter, r *http.Request) {
	err := recover()
	if nil != err {
		w.WriteHeader(http.StatusInternalServerError)
		stack := make([]byte, 1<<16)
		runtime.Stack(stack, false)
		log.Printf("HTTP error %s\n%s", err, stack)
	}
}

func (self *EventHandler) compareSignatures(payload, signature []byte) bool {
	mac := hmac.New(sha1.New, self.signatureKey)
	mac.Write(payload)
	expected := mac.Sum(nil)
	actual := make([]byte, 20)
	hex.Decode(actual, signature)
	return hmac.Equal(actual, expected)
}
