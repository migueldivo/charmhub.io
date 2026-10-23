import os

import requests
from canonicalwebteam.exceptions import StoreApiResponseErrorList
from canonicalwebteam.store_api.devicegw import DeviceGW
from canonicalwebteam.store_api.publishergw import PublisherGW
from flask import current_app, has_app_context
from webapp.observability.utils import trace_function


def decorate_all_methods(decorator, cls):
    class WrappedClass(cls):
        pass

    for attr_name in dir(cls):
        # ignore private and special methods like __init__ etc.
        if attr_name.startswith("__"):
            continue
        attr = getattr(cls, attr_name)
        # only decorate callable attributes (these are mostly API calls)
        if callable(attr):
            setattr(WrappedClass, attr_name, decorator(attr))

    return WrappedClass


TracedPubilsherGW = decorate_all_methods(trace_function, PublisherGW)
TracedDeviceGW = decorate_all_methods(trace_function, DeviceGW)


def get_charm_allowlist():
    """
    Local demo filter: when CHARM_ALLOWLIST_FILE is set, only the package
    names listed in that file (one per line, # for comments) are exposed.
    The file is re-read on every call so edits apply without a restart.
    The filter is skipped when the Flask app is in testing mode.
    """
    if has_app_context() and current_app.testing:
        return None

    path = os.getenv("CHARM_ALLOWLIST_FILE", "").strip()
    if not path:
        return None

    with open(path) as allowlist_file:
        lines = (line.split("#", 1)[0].strip() for line in allowlist_file)
        return {line for line in lines if line}


class CharmAllowlistMixin:
    def find(self, *args, **kwargs):
        response = super().find(*args, **kwargs)
        allowlist = get_charm_allowlist()
        if allowlist is not None and "results" in response:
            response["results"] = [
                package
                for package in response["results"]
                if package.get("name") in allowlist
            ]
        return response

    def get_item_details(self, name, *args, **kwargs):
        allowlist = get_charm_allowlist()
        if allowlist is not None and name not in allowlist:
            raise StoreApiResponseErrorList("Entity not found", 404, [])
        return super().get_item_details(name, *args, **kwargs)


class AllowlistedPublisherGW(CharmAllowlistMixin, TracedPubilsherGW):
    pass


class AllowlistedDeviceGW(CharmAllowlistMixin, TracedDeviceGW):
    pass


request_session = requests.Session()
publisher_gateway = AllowlistedPublisherGW("charm", request_session)
device_gateway = AllowlistedDeviceGW("charm", request_session)
device_gateway_sbom = TracedDeviceGW("sbom", request_session)
