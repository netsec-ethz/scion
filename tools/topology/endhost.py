# Copyright 2024 ETH Zurich, Anapaya Systems
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Stdlib
from typing import Mapping

# SCION
from topology.net import NetworkDescription, IPNetwork


def endhost_ip(docker, topo_id,
               networks: Mapping[IPNetwork, NetworkDescription]):
    for net_desc in networks.values():
        for prog, ip_net in net_desc.ip_net.items():
            if prog == 'endhost_%s' % topo_id.file_fmt():
                return ip_net.ip
    return None
