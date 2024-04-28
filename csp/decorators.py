from functools import wraps


def csp_exempt(f):
    @wraps(f)
    def _wrapped(*a, **kw):
        r = f(*a, **kw)
        r._csp_exempt = True
        return r

    return _wrapped


# TODO: By passing a dict here, we can only update one policy, not both. Hmm.
def csp_update(update):
    def decorator(f):
        @wraps(f)
        def _wrapped(*a, **kw):
            r = f(*a, **kw)
            r._csp_update = update
            return r

        return _wrapped

    return decorator


def csp_replace(replace):
    def decorator(f):
        @wraps(f)
        def _wrapped(*a, **kw):
            r = f(*a, **kw)
            r._csp_replace = replace
            return r

        return _wrapped

    return decorator


def csp(config):
    def decorator(f):
        @wraps(f)
        def _wrapped(*a, **kw):
            r = f(*a, **kw)
            r._csp_config = config
            return r

        return _wrapped

    return decorator
