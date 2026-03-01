# roxy-plugin-sdk

Python SDK for Roxy plugins.

## Install

```bash
pip install .
```

or from repository root:

```bash
pip install ./python/roxy-plugin-sdk
```

## Use

```python
from roxy_plugin_sdk import PluginBuilder, RoxyClient, run_plugin

def handle(hook, payload):
    builder = PluginBuilder()
    if hook == "on_request_pre_capture":
        request = payload.get("request", {})
        raw = request.get("raw_text", "")
        builder.set_request_raw_text(raw.replace("foo", "bar"))
    return builder.to_dict()

run_plugin(handle)
```
