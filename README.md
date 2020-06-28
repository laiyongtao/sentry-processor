# sentry-processor
sentry event processor for protecting sensitive infos. 

#### Demo:
```python
import sentry_sdk
from sentry_sdk.integrations.logging import LoggingIntegration
from sentry_processor import DesensitizationProcessor, POSITION

'''
# origin:
{
    ...
    "vars": {
        "pwd": "12345!@#$%",
        "phone": "13012341234"
    }
    ...
}
# result:
{
    ...
    "vars": {
        "pwd": "********",
        "phone": "130****1234"
    }
    ...
}
'''

def before_send(event, hint):
    # https://docs.sentry.io/error-reporting/configuration/filtering/?platform=python
    # modify event here
    # ...

    # process sensitive infos
    processor = DesensitizationProcessor(
        sensitive_keys=["pwd"],
        with_default_keys=True,
        partial_keys=["phone"],
        mask_position=POSITION.RIGHT,
        off_set=4
    )
    event = processor(event, hint)
    # or
    # event = processor.process(event, hint)

    return event


sentry_sdk.init(
    dsn="dsn",
    integrations=[LoggingIntegration()],
    before_send=before_send
)
```
#### API Reference
```text
class DesensitizationProcessor(sensitive_keys=None, mask=None, with_default_keys=True,
                               partial_keys=None, partial_mask=None, mask_position=POSITION.RIGHT, off_set=0)
     Parameters:
        - sensitive_keys:
            A list of sensitive information keys that need to be filtered
            required: false
        - mask:
            The string to replace sensitive informations 
            required: false
        - with_default_keys:
            Whether to use the default sensitive information keys
            required: false
            default: True
        - partial_keys:
            A list of sensitive information keys that need to partially hidden(e.g: "12345678" -> "1234****")
            required: false
        - partial_mask:
            The string to partially hidden sensitive informations
            required: false
        - off_set:
            offset of partial_mask string relative to the starting point
            required: false
            default: 0
        - mask_position:
            starting point, the left or right side of original string
            required: false
            default: POSITION.RIGHT       
    
    process(self, event, hint)
        - event
        - hint

    __call__(self, event, hint)
        - event
        - hint
```