# terminus
A TCP router.

## Note
After TLS and HTTP, a fallback protocol is supported where everything up to the first newline or 255 bytes is considered to be a server "id". You can use this mechanism to route arbitrary protocols (if you control the initiator). To be considered for matching against ids, hosts must opt-in by exposing their names array on host.ids instead of host.names.

## License
Public domain
