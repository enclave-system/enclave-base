def pytest_configure(config):
    config.addinivalue_line("markers", "vm: boots a QEMU VM (slow; deselect with -m 'not vm')")
