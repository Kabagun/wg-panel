"""Native routing metadata must preserve the selected client DNS behavior."""
import base64
import copy
import json

import pytest

from wg_panel.happ_pilot import HappStateError, routing_header


def config(strategy):
    return {'dns': {'servers': ['tcp://192.0.2.53']},
            'routing': {'domainStrategy': strategy, 'rules': [
                {'outboundTag': 'direct', 'ip': ['geoip:by', 'geoip:ru']}]}}


@pytest.mark.parametrize('strategy', ['IPOnDemand', 'AsIs'])
def test_native_header_matches_json_resolution_strategy_and_keeps_same_dns(strategy):
    configs = [config(strategy), config(strategy)]
    before = copy.deepcopy(configs)
    link = routing_header({'wg_name': 'synthetic-device'}, 'bundle', configs)
    profile = json.loads(base64.b64decode(link.removeprefix('happ://routing/onadd/')))
    assert profile['DomainStrategy'] == strategy
    assert profile['RemoteDNSIP'] == profile['DomesticDNSIP'] == '192.0.2.53'
    assert profile['RemoteDNSType'] == profile['DomesticDNSType'] == 'DoU'
    assert profile['DirectIp'] == ['geoip:by', 'geoip:ru']
    assert configs == before


@pytest.mark.parametrize('strategies', [('AsIs', 'IPOnDemand'), ('localhost', 'localhost'),
                                       (None, None), (True, True)])
def test_mixed_or_invalid_resolution_strategy_cannot_silently_override_native_routing(strategies):
    with pytest.raises(HappStateError):
        routing_header({'wg_name': 'synthetic-device'}, 'bundle', [config(s) for s in strategies])
