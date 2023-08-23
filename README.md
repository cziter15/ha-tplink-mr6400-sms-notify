# TP-Link MR6400 SMS Notify - mr6400sms
[![hacs_badge](https://img.shields.io/badge/HACS-Custom-41BDF5.svg)](https://github.com/hacs/integration) [![Validate with hassfest](https://github.com/cziter15/ha-tplink-mr6400-sms-notify/actions/workflows/hassfest.yml/badge.svg)](https://github.com/cziter15/ha-tplink-mr6400-sms-notify/actions/workflows/hassfest.yml)

The TP-Link MR6400 SMS Notify, known as **mr6400sms**, is an integration for HomeAssistant HACS that offers a significantly faster alternative to tp-connected. It achieves this speed boost by eliminating js2py-based cryptography while still being based on the reliable tp-connected code.

## Configuration

To set up the TP-Link MR6400 SMS Notify integration, follow these steps:

1. In your `configuration.yaml` file, add the following configuration:

```yaml
notify:
  - platform: mr6400sms
    name: mr6400sms
    router_ip: <IP of the router>
    router_pwd: <admin password>
Replace <IP of the router> with the actual IP address of your TP-Link MR6400 router, and <admin password> with your router's administrator password.
```

## Using the Service
Once you've configured the integration, you can call the service to send SMS messages. Here are some key points to note:

- You can send SMS messages to multiple numbers.
- The title parameter is ignored; you only need to specify the message content and the target numbers.

Here's an example of how to call the service in your HomeAssistant automation:

```yaml
service: notify.mr6400sms
data:
  message: Test SMS message content
  target:
    - number1
    - number2
```

## TODOs (To-Do List)
I have some improvements and tasks on my radar to enhance this integration:

- Consider implementing outbox cleanup for better management of sent messages.
- Develop a user-friendly UI-based configuration option to simplify setup.
- Enhance code readability by adding comments and documentation.
- Address and fix any validation warnings to ensure a seamless user experience.

I am committed to continually improving the TP-Link MR6400 SMS Notify integration to make it even more efficient and user-friendly. Your feedback and contributions are highly appreciated!
