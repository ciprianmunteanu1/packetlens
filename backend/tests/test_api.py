import requests

BASE_URL = "http://127.0.0.1:8000"


def test_post_all_packets():
    url = f"{BASE_URL}/packets/all"
    resp = requests.post(url)
    print("POST /packets/all", resp.status_code, resp.json())


def test_post_iface_packets():
    iface = "lo0"
    url = f"{BASE_URL}/packets/interface/{iface}"
    resp = requests.post(url)
    print(f"POST /packets/interface/{iface}", resp.status_code, resp.json())


def test_get_all_packets():
    url = f"{BASE_URL}/packets"
    resp = requests.get(url)
    print("GET /packets", resp.status_code, resp.json())


def test_filter_by_protocol():
    url = f"{BASE_URL}/packets/by_protocol"
    params = {"protocol": "tcp"}
    resp = requests.get(url, params=params)
    print("GET /packets/by_protocol", resp.status_code, resp.json())


def test_filter_by_interface():
    url = f"{BASE_URL}/packets/by_interface"
    params = {"interface": "lo0"}
    resp = requests.get(url, params=params)
    print("GET /packets/by_interface", resp.status_code, resp.json())


def test_filter_by_ip():
    url = f"{BASE_URL}/packets/by_ip"
    params = {"src_ip": "127.0.0.1"}
    resp = requests.get(url, params=params)
    print("GET /packets/by_ip", resp.status_code, resp.json())


def test_filter_by_icmp_type():
    url = f"{BASE_URL}/packets/by_icmp_type"
    params = {"icmp_type": "echo-request"}
    resp = requests.get(url, params=params)
    print("GET /packets/by_icmp_type", resp.status_code, resp.json())


def test_filter_by_eth_type():
    url = f"{BASE_URL}/packets/by_eth_type"
    params = {"eth_type": "0800"}
    resp = requests.get(url, params=params)
    print("GET /packets/by_eth_type", resp.status_code, resp.json())


def test_filter_by_time_range():
    url = f"{BASE_URL}/packets/by_time_range"
    params = {
        "start_ts": "2025-07-16 00:00:00",
        "end_ts": "2025-07-16 23:59:59"
    }
    resp = requests.get(url, params=params)
    print("GET /packets/by_time_range", resp.status_code, resp.json())


def test_filter_by_payload_size():
    url = f"{BASE_URL}/packets/by_payload_size"
    params = {"min_size": 10}
    resp = requests.get(url, params=params)
    print("GET /packets/by_payload_size", resp.status_code, resp.json())


def test_filter_by_mac():
    url = f"{BASE_URL}/packets/by_mac"
    params = {"src_mac": "00:00:00:00:00:00"}
    resp = requests.get(url, params=params)
    print("GET /packets/by_mac", resp.status_code, resp.json())


def test_filter_by_port_range():
    url = f"{BASE_URL}/packets/by_port_range"
    params = {"start_port": 20, "end_port": 80}
    resp = requests.get(url, params=params)
    print("GET /packets/by_port_range", resp.status_code, resp.json())


def test_filter_by_flags():
    url = f"{BASE_URL}/packets/by_flags"
    params = [("flags", "SYN"), ("flags", "ACK")]
    resp = requests.get(url, params=params)
    print("GET /packets/by_flags", resp.status_code, resp.json())


def test_filter_combined():
    url = f"{BASE_URL}/packets/filter"
    params = {
        "protocol": "tcp",
        "src_ip": "127.0.0.1",
    }
    resp = requests.get(url, params=params)
    print("GET /packets/filter", resp.status_code, resp.json())


def test_count_by_protocol():
    url = f"{BASE_URL}/packets/count_by_protocol"
    params = {"protocol": "tcp"}
    resp = requests.get(url, params=params)
    print("GET /packets/count_by_protocol", resp.status_code, resp.json())


def test_delete_all():
    url = f"{BASE_URL}/packets"
    resp = requests.delete(url)
    print("DELETE /packets", resp.status_code, resp.json())


if __name__ == "__main__":
    test_post_all_packets()
    test_post_iface_packets()
    test_get_all_packets()
    test_filter_by_protocol()
    test_filter_by_interface()
    test_filter_by_ip()
    test_filter_by_icmp_type()
    test_filter_by_eth_type()
    test_filter_by_time_range()
    test_filter_by_payload_size()
    test_filter_by_mac()
    test_filter_by_port_range()
    test_filter_by_flags()
    test_filter_combined()
    test_count_by_protocol()
    test_delete_all()
