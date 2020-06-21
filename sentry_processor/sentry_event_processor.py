# coding=utf-8
from .raven_codes import SanitizeKeysProcessor, text_type
from enum import IntEnum, unique

@unique
class POSITION(IntEnum):
    LEFT = 1
    RIGHT = 2


class DesensitizationProcessor(SanitizeKeysProcessor):
    DEFAULT_KEYS = {
        "password",
        "secret",
        "passwd",
        "api_key",
        "apikey",
        "dsn",
        "token",
    }

    SYMBOL = "*"
    MASK = SYMBOL * 8
    PARTIAL_MASK = SYMBOL * 4

    def __init__(self, sensitive_keys=None, mask=None, with_default_keys=True,
                 partial_keys=None, partial_mask=None, mask_postions=POSITION.RIGHT, off_set=0):
        if not sensitive_keys:
            sensitive_keys = set()
        if not partial_keys:
            partial_keys = set()
        self._sensitive_keys = set(sensitive_keys) | self.DEFAULT_KEYS if with_default_keys else set(sensitive_keys)
        self.partial_keys = partial_keys
        if mask is not None:
            self.MASK = mask
        if partial_mask is not None:
            self.PARTIAL_MASK = partial_mask

        self._part_len = len(self.PARTIAL_MASK)

        for p in POSITION:
            if mask_postions == p: break
        else:
            raise ValueError("The value of mask_postions must be one of the options of POSITION")

    @property
    def sanitize_keys(self):
        return self._sensitive_keys

    def partly_mask(self, value):
        # TODO:
        return value

    def sanitize(self, item, value):
        if value is None:
            return

        if not item:
            return value

        if isinstance(item, bytes):
            item = item.decode('utf-8', 'replace')
        else:
            item = text_type(item)

        item = item.lower()
        for key in self.sanitize_keys:
            if key in item:
                return self.MASK
        for key in self.partial_keys:
            if key in item:
                return self.partly_mask(value)

        return value

    def __call__(self, data, hint):

        if 'exception' in data:
            if 'values' in data['exception']:
                for value in data['exception'].get('values', []):
                    if 'stacktrace' in value:
                        self.filter_stacktrace(value['stacktrace'])

        if 'request' in data:
            self.filter_http(data['request'])

        if 'extra' in data:
            data['extra'] = self.filter_extra(data['extra'])

        return data


if __name__ == '__main__':
    pass
