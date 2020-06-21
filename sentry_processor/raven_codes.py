# coding=utf-8
'''
https://github.com/getsentry/raven-python
'''
import sys
PY3 = sys.version_info[0] == 3

try:
    from collections.abc import Mapping
except ImportError:
    # Python < 3.3
    from collections import Mapping

if PY3:
    string_types = str,
    text_type = str
    def iteritems(d, **kw):
        return iter(d.items(**kw))

else:
    string_types = basestring,
    text_type = unicode
    def iteritems(d, **kw):
        return d.iteritems(**kw)



def varmap(func, var, context=None, name=None):
    """
    Executes ``func(key_name, value)`` on all values
    recurisively discovering dict and list scoped
    values.
    """
    if context is None:
        context = {}
    objid = id(var)
    if objid in context:
        return func(name, '<...>')
    context[objid] = 1

    if isinstance(var, (list, tuple)) and not is_namedtuple(var):
        ret = [varmap(func, f, context, name) for f in var]
    else:
        ret = func(name, var)
        if isinstance(ret, Mapping):
            ret = dict((k, varmap(func, v, context, k))
                       for k, v in iteritems(var))
    del context[objid]
    return ret


def is_namedtuple(value):
    # https://stackoverflow.com/a/2166841/1843746
    # But modified to handle subclasses of namedtuples.
    if not isinstance(value, tuple):
        return False
    f = getattr(type(value), '_fields', None)
    if not isinstance(f, tuple):
        return False
    return all(type(n) == str for n in f)


class SanitizeKeysProcessor(object):
    """
    Asterisk out things that correspond to a configurable set of keys.
    """

    MASK = '*' * 8

    @property
    def sanitize_keys(self):
        keys = getattr(self.client, 'sanitize_keys')
        if keys is None:
            raise ValueError('The sanitize_keys setting must be present to use SanitizeKeysProcessor')
        return keys

    def sanitize(self, item, value):
        if value is None:
            return

        if not item:  # key can be a NoneType
            return value

        # Just in case we have bytes here, we want to make them into text
        # properly without failing so we can perform our check.
        if isinstance(item, bytes):
            item = item.decode('utf-8', 'replace')
        else:
            item = text_type(item)

        item = item.lower()
        for key in self.sanitize_keys:
            if key in item:
                # store mask as a fixed length for security
                return self.MASK
        return value

    def filter_stacktrace(self, data):
        for frame in data.get('frames', []):
            if 'vars' not in frame:
                continue
            frame['vars'] = varmap(self.sanitize, frame['vars'])

    def filter_http(self, data):
        for n in ('data', 'cookies', 'headers', 'env', 'query_string'):
            if n not in data:
                continue

            # data could be provided as bytes
            if PY3 and isinstance(data[n], bytes):
                data[n] = data[n].decode('utf-8', 'replace')

            if isinstance(data[n], string_types) and '=' in data[n]:
                # at this point we've assumed it's a standard HTTP query
                # or cookie
                if n == 'cookies':
                    delimiter = ';'
                else:
                    delimiter = '&'

                data[n] = self._sanitize_keyvals(data[n], delimiter)
            else:
                data[n] = varmap(self.sanitize, data[n])
                if n == 'headers' and 'Cookie' in data[n]:
                    data[n]['Cookie'] = self._sanitize_keyvals(
                        data[n]['Cookie'], ';'
                    )

    def filter_extra(self, data):
        return varmap(self.sanitize, data)

    def _sanitize_keyvals(self, keyvals, delimiter):
        sanitized_keyvals = []
        for keyval in keyvals.split(delimiter):
            keyval = keyval.split('=')
            if len(keyval) == 2:
                sanitized_keyvals.append((keyval[0], self.sanitize(*keyval)))
            else:
                sanitized_keyvals.append(keyval)

        return delimiter.join('='.join(keyval) for keyval in sanitized_keyvals)
