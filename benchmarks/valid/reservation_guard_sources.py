"""Frozen exact identities for retained legacy reservation source files."""

from types import MappingProxyType

PINNED_LEGACY_RESERVATION_SOURCE_DIGESTS = MappingProxyType(
    {
        "benchmarks/independent/candidates-v3-php.json": "38f818c058d5d67e7c2861225bb37f29d1f279f213bed3d363f9eaf695cfd04e",
        "benchmarks/independent/freeze-v1.json": "2c9ca1be6386a2053b34532e573195201c4bbd5db1cdf0f6b8678c311246e330",
        "benchmarks/independent/freeze-v2.json": "83335e0ee49dd88f6e7c2b7d856b20da22e0572e5fe360d30f0ff7552c518b07",
        "benchmarks/independent/freeze-v3-php.json": "ad372911ee90b2437f777ff4db128421028d7c0c6eafab7da768e97cb25163f2",
        "benchmarks/independent/research-2026-09-24.md": "2c24df48d93f4cd6bdc71b1b990afacd0de5314127041a9b786baf5c33b4810a",
        "benchmarks/independent/research-2026-09-26.md": "905da0feae5fa1d5e5c71dfc7bca9d6a2ca208fbe30a82345a8209c81d0ab3b6",
        "benchmarks/independent/research-2026-09-30-php.md": "8b87fef5a7d73ff71c23e9b7fb64a0756124ad2429fbffa8df54e87abb8e8feb",
        "benchmarks/measurements/2026-10-12-valid-benchmark-pilot/catalog.toml": (
            "32d1353325c475826fde62008225779032cc2f4750a2c7550fc1b7fc933fcdd4"
        ),
        "benchmarks/measurements/2026-10-12-valid-benchmark-pilot/sources.json": (
            "c867d7cbb45948de48fb359cdf864085d9c7fdd333a2077d1a79c4f62ef59b7f"
        ),
        "benchmarks/pairs/advisory-fixes/catalog.toml": "dc2a34db001e02294d43b25183b0e04ff91497beb48e7c50d0945791e4ea7e86",
        "benchmarks/pairs/advisory-fixes/research-2026-10-01.md": "095fadc612fdc9d9a269bf36998c5b6bc694fa718b90d739180aae451d247e9a",
        "plane/tasks/validation-46.yaml": "3ff9607cc6aa8c769caa816966b68d8506c3b21f342e3e9f7a84c53b42bb8139",
        "plane/workspaces/budibase-mongo-template-nosqli-vulnerable.yaml": (
            "ce45f9a4eade0695205a26dff4c3c3a060f2818dab5d764615040ad7bea9db57"
        ),
        "plane/workspaces/cct-studio-server-cmdi-vulnerable.yaml": "7759599f0097ef9d90ed7eafdec1193c0eac0460ee06c20d932622c5adf30590",
        "plane/workspaces/contextforge-prompt-ssti-vulnerable.yaml": "7d81b46da34a501a1ce280845649720a5df74e9269dcd400311ed9a0666d42d0",
        "plane/workspaces/froxlor-admin-ip-second-order-sqli-vulnerable.yaml": (
            "f7c0b9570c679e5a451e44f8e44720fabf8db3ec7bc401e224e983ef176ff760"
        ),
        "plane/workspaces/fuxa-tdengine-escape-sqli-vulnerable.yaml": "a6453130ab9c3ab27b81414568ba70e61161aead0d84953d8344141317c87351",
        "plane/workspaces/lmdeploy-media-url-ssrf-vulnerable.yaml": "e42aad434cce797949d14ab0368f87eb23985fb4b44feaec0c4f6c4b95f03fd9",
        "plane/workspaces/medplum-external-auth-open-redirect-vulnerable.yaml": (
            "6228e5cb9aa2ddb9c0b33c9775ee094eb026a1cff1e3dbfff4a28b2ab7b3a64d"
        ),
        "plane/workspaces/pgadmin-maintenance-sqli-vulnerable.yaml": "fc64de599a0ef123bb01d63691aa7d3602596c81b419942252aee656e90257f0",
        "plane/workspaces/qwed-sympy-eval-vulnerable.yaml": "4a0d29e8e73cf71d0fafbd36b828426b345b94d380dc875d1daa9df000aa1c61",
        "plane/workspaces/reactpress-findall-column-sqli-vulnerable.yaml": (
            "d4f9701723e91049437bd1f42067bc638e342752e2d71eaf23dcbc070274e265"
        ),
        "plane/workspaces/unleash-addon-webhook-ssrf-vulnerable.yaml": "82467a84cdd231a0aacf4919b3a3009f83ea5e023fa50197a80d0a19f455ded5",
        "plane/workspaces/winml-cli-serve-cors-vulnerable.yaml": "cab02c399c98f2f8916642535c8ac918d90457dbff5a3860008be98bd2a20357",
        "plane/workspaces/wp-directorist-avatar-ssrf-vulnerable.yaml": "abc7eeb27297bc43a955c1d4fdfe8b1aa35e161fdf423a25ff22200bd781068b",
        "plane/workspaces/wp-gopay-log-filter-sqli-vulnerable.yaml": "160f69b6d9c379563ee384a807f6ebffe8733c1557a04a4768a8585673fd41be",
        "plane/workspaces/wp-groundhogg-confirm-redirect-vulnerable.yaml": (
            "f93ab3a76791535392e2350ce7914815417faad1fb755990a551fc25650c08a1"
        ),
    }
)

__all__ = ["PINNED_LEGACY_RESERVATION_SOURCE_DIGESTS"]
