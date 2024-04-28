import copy
import re
from collections import OrderedDict
from itertools import chain

from django.conf import settings
from django.utils.encoding import force_str


DEFAULT_CONFIG = {
    "EXCLUDE_URL_PREFIXES": [],
    "INCLUDE_NONCE_IN": [],
    "REPORT_ONLY": False,
    "REPORT_PERCENTAGE": 0,  # An integer between 0 and 100.
}


DEFAULT_DIRECTIVES = {
    # Fetch Directives
    "child-src": None,
    "connect-src": None,
    "default-src": ["'self'"],
    "script-src": None,
    "script-src-attr": None,
    "script-src-elem": None,
    "object-src": None,
    "style-src": None,
    "style-src-attr": None,
    "style-src-elem": None,
    "font-src": None,
    "frame-src": None,
    "img-src": None,
    "manifest-src": None,
    "media-src": None,
    "prefetch-src": None,  # Deprecated.
    # Document Directives
    "base-uri": None,
    "plugin-types": None,  # Deprecated.
    "sandbox": None,
    # Navigation Directives
    "form-action": None,
    "frame-ancestors": None,
    "navigate-to": None,
    # Reporting Directives
    "report-uri": None,
    "report-to": None,
    "require-sri-for": None,
    # Trusted Types Directives
    "require-trusted-types-for": None,
    "trusted-types": None,
    # Other Directives
    "webrtc": None,
    "worker-src": None,
    #
    "upgrade-insecure-requests": False,
    "block-all-mixed-content": False,  # Deprecated.
}


def from_settings():
    CSP = getattr(settings, "CONTENT_SECURITY_POLICY", [{}])[0]
    config = {"DIRECTIVES": {}}
    for key, value in DEFAULT_CONFIG.items():
        config[key] = CSP.get(key, value)
    for key, value in DEFAULT_DIRECTIVES.items():
        config["DIRECTIVES"][key] = CSP.get("DIRECTIVES", {}).get(key, value)
    return config


def build_policy(config=None, update=None, replace=None, nonce=None):
    """Builds the policy as a string from the settings."""

    # TODO: If `report-to` is set, also add a `Report-To` header.
    # TODO: Consider using `set`s here to de-dupe values?

    if config is None:
        config = from_settings()
        # Be careful, don't mutate config as it could be from settings

    update = update if update is not None else {}
    replace = replace if replace is not None else {}

    csp = {"DIRECTIVES": {}}

    for k in set(chain(config["DIRECTIVES"], replace)):
        if k in replace:
            v = replace[k]
        else:
            v = config["DIRECTIVES"][k]
        if v is not None:
            v = copy.copy(v)
            if not isinstance(v, (list, tuple)):
                v = (v,)
            csp["DIRECTIVES"][k] = v

    for k, v in update.items():
        if v is not None:
            if not isinstance(v, (list, tuple)):
                v = (v,)
            if csp["DIRECTIVES"].get(k) is None:
                csp["DIRECTIVES"][k] = v
            else:
                csp["DIRECTIVES"][k] += tuple(v)

    report_uri = csp["DIRECTIVES"].pop("report-uri", None)

    policy_parts = {}
    for key, value in csp["DIRECTIVES"].items():
        # flag directives with an empty directive value
        if len(value) and value[0] is True:
            policy_parts[key] = ""
        elif len(value) and value[0] is False:
            pass
        else:  # directives with many values like src lists
            policy_parts[key] = " ".join(value)

    if report_uri:
        report_uri = map(force_str, report_uri)
        policy_parts["report-uri"] = " ".join(report_uri)

    if nonce:
        include_nonce_in = config.get("INCLUDE_NONCE_IN", ["default-src"])
        for section in include_nonce_in:
            policy = policy_parts.get(section, "")
            policy_parts[section] = f"{policy} 'nonce-{nonce}'".strip()

    return "; ".join([f"{k} {val}".strip() for k, val in policy_parts.items()])


def _default_attr_mapper(attr_name, val):
    if val:
        return f' {attr_name}="{val}"'
    else:
        return ""


def _bool_attr_mapper(attr_name, val):
    # Only return the bare word if the value is truthy
    # ie - defer=False should actually return an empty string
    if val:
        return f" {attr_name}"
    else:
        return ""


def _async_attr_mapper(attr_name, val):
    """The `async` attribute works slightly different than the other bool
    attributes. It can be set explicitly to `false` with no surrounding quotes
    according to the spec."""
    if val in [False, "False"]:
        return f" {attr_name}=false"
    elif val:
        return f" {attr_name}"
    else:
        return ""


# Allow per-attribute customization of returned string template
SCRIPT_ATTRS = OrderedDict()
SCRIPT_ATTRS["nonce"] = _default_attr_mapper
SCRIPT_ATTRS["id"] = _default_attr_mapper
SCRIPT_ATTRS["src"] = _default_attr_mapper
SCRIPT_ATTRS["type"] = _default_attr_mapper
SCRIPT_ATTRS["async"] = _async_attr_mapper
SCRIPT_ATTRS["defer"] = _bool_attr_mapper
SCRIPT_ATTRS["integrity"] = _default_attr_mapper
SCRIPT_ATTRS["nomodule"] = _bool_attr_mapper

# Generates an interpolatable string of valid attrs eg - '{nonce}{id}...'
ATTR_FORMAT_STR = "".join([f"{{{a}}}" for a in SCRIPT_ATTRS])


_script_tag_contents_re = re.compile(
    r"""<script        # match the opening script tag
            [\s|\S]*?> # minimally match attrs and spaces in opening script tag
    ([\s|\S]+)         # greedily capture the script tag contents
    </script>          # match the closing script tag
""",
    re.VERBOSE,
)


def _unwrap_script(text):
    """Extract content defined between script tags"""
    matches = re.search(_script_tag_contents_re, text)
    if matches and len(matches.groups()):
        return matches.group(1).strip()

    return text


def build_script_tag(content=None, **kwargs):
    data = {}
    # Iterate all possible script attrs instead of kwargs to make
    # interpolation as easy as possible below
    for attr_name, mapper in SCRIPT_ATTRS.items():
        data[attr_name] = mapper(attr_name, kwargs.get(attr_name))

    # Don't render block contents if the script has a 'src' attribute
    c = _unwrap_script(content) if content and not kwargs.get("src") else ""
    attrs = ATTR_FORMAT_STR.format(**data).rstrip()
    return f"<script{attrs}>{c}</script>".strip()
