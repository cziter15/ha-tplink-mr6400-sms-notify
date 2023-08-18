# mr6400sms
This is HomeAssistant HACS integration that works a lot faster than tp-connected due to eliminated js2py based cryptography.
This code however is based on tp-connected.

## In your configuration.yaml add this:
```yaml
notify:
  - platform: mr6400sms
    name: mr6400sms
    router_ip: <IP of the router>
    router_pwd: <admin password>
```

## Calling the service
- Multiple numbers supported
- Title parameter is ignored

```yaml
service: notify.mr6400sms
data:
  message: Test SMS message content
  target:
    - number1
    - number2
```
