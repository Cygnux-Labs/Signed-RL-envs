from pep440lite import sort_versions

from registry_snapshot import ORDER


def test_orders_like_the_package_index():
    assert sort_versions(list(reversed(ORDER))) == ORDER
