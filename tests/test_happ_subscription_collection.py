"""The actual Xray collector feeds independent, correctly directed subscription usage."""
import json

from test_happ_runtime import runtime  # noqa: F401 - shared synthetic fixture

from wg_panel import happ_runtime, traffic
from wg_panel.happ_subscription_usage import read_usage


def test_collector_direction_restart_and_missing_counters(runtime, monkeypatch):  # noqa: F811
    path, _user, _device, _calls = runtime
    happ_runtime.provision('test-phone')
    record = json.loads((path / 'happ_protocol_devices.json').read_bytes())['devices']['test-phone']
    generation = ['first']
    values = {'uplink': 100, 'downlink': 200}
    def run(args, **kwargs):
        if 'statsquery' in args:
            return json.dumps({'stat': [{'name': f"user>>>{record['email']}>>>traffic>>>{direction}",
                                         'value': value} for direction, value in values.items()]})
        return generation[0]
    monkeypatch.setattr(happ_runtime, '_run', run)
    happ_runtime.collect_traffic()
    assert read_usage(traffic.load_traffic()['test-phone'])['upload'] == 0
    values.update(uplink=110, downlink=230)
    happ_runtime.collect_traffic()
    result = read_usage(traffic.load_traffic()['test-phone'])
    assert (result['upload'], result['download']) == (10, 30)
    happ_runtime.collect_traffic()
    assert read_usage(traffic.load_traffic()['test-phone']) == result
    generation[0] = 'second'
    values.update(uplink=3, downlink=7)
    happ_runtime.collect_traffic()
    result = read_usage(traffic.load_traffic()['test-phone'])
    assert (result['upload'], result['download']) == (13, 37)
    values.clear()
    happ_runtime.collect_traffic()
    assert read_usage(traffic.load_traffic()['test-phone']) == result
    values.update(uplink=5, downlink=9)
    happ_runtime.collect_traffic()
    result = read_usage(traffic.load_traffic()['test-phone'])
    assert (result['upload'], result['download']) == (15, 39)
