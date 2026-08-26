EXAMPLE_TOPOLOGY = {
    "nodes": [
        {
            "name": "sg-browser",
            "endpoint": "https://control-edge.example.com",
            "expected_public_ipv4": "192.0.2.10",
            "enabled": True,
        },
        {
            "name": "edge-sg01",
            "endpoint": "https://edge-sg.example.com",
            "expected_public_ipv4": "198.51.100.20",
            "enabled": True,
        },
        {
            "name": "edge-hk01",
            "endpoint": "https://edge-hk.example.com",
            "expected_public_ipv4": "203.0.113.30",
            "enabled": True,
        },
    ],
    "stores": [
        {"name": "Store 01", "node": "sg-browser", "enabled": True},
        {"name": "Store 02", "node": "edge-sg01", "enabled": True},
        {"name": "Store 03", "node": "edge-hk01", "enabled": True},
    ],
}
