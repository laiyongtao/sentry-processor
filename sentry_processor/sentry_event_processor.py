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

    MASK = "*" * 8
    PARTIAL_MASK = "*" * 4

    def __init__(self, sensitive_keys=None, mask=None, with_default_keys=True,
                 partial_keys=None, partial_mask=None, mask_position=POSITION.RIGHT, off_set=0):
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
        self.PARTIAL_MASK = text_type(self.PARTIAL_MASK)
        self._part_len = len(self.PARTIAL_MASK)

        for p in POSITION:
            if mask_position == p: break
        else:
            raise ValueError("The value of mask_postions must be one of the options of POSITION")

        self.mask_position = mask_position

        self.off_set = abs(int(off_set))

    @property
    def sanitize_keys(self):
        return self._sensitive_keys

    def partly_mask(self, value):
        value_len = len(value)
        if value_len <= self._part_len:
            return self.PARTIAL_MASK

        off_set = self.off_set if value_len >= (self._part_len + self.off_set) else (value_len - self._part_len)

        if self.mask_position == POSITION.LEFT:
            lp = value[:off_set]
            rp = value[off_set + self._part_len:]
        else:
            rp = value[-off_set:] if off_set != 0 else ""
            lp = value[:-(off_set + self._part_len)]

        return lp + self.PARTIAL_MASK + rp

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

    def process(self, event, hint):
        if 'exception' in event:
            if 'values' in event['exception']:
                for value in event['exception'].get('values', []):
                    if 'stacktrace' in value:
                        self.filter_stacktrace(value['stacktrace'])

        if 'request' in event:
            self.filter_http(event['request'])

        if 'extra' in event:
            event['extra'] = self.filter_extra(event['extra'])

        return event

    def __call__(self, event, hint):
        return self.process(event, hint)


if __name__ == '__main__':
    pass
