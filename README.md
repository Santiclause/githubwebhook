GitHub Webhooks
===============
Simple GitHub webhook event handler. Lets you add hooks to act upon GitHub
webhooks.

Example Usage
=============

```
func main() {
	handler := webhook.NewEventHandler(config.SignatureKey)
	handler.AddHook("pull_request", func(event string, body []byte){
        //do stuff
    })
	http.HandleFunc("/webhook", handler.Handler())
	http.ListenAndServe(":11111", nil)
}
```
