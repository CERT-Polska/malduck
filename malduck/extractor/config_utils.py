from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    from typing_extensions import TypeAlias

    Config: TypeAlias = dict[str, Any]
    ConfigSet: TypeAlias = dict[str, Config]


log = logging.getLogger(__name__)


def is_config_better(base_config: Config, new_config: Config) -> bool:
    """
    Checks whether new config looks more reliable than base.
    Currently just checking the amount of non-empty keys.
    """
    return (
        len(tuple(filter(None, new_config.values())))
        > len(tuple(filter(None, base_config.values())))
    )


def encode_for_json(data: Any) -> Any:
    if isinstance(data, bytes):
        return data.decode()
    elif isinstance(data, list) or isinstance(data, tuple):
        return [encode_for_json(item) for item in data]
    elif isinstance(data, dict):
        return {key: encode_for_json(value) for key, value in data.items()}
    else:
        return data


def sanitize_config(config: Config) -> Config:
    """
    Sanitize static configuration by removing empty strings/collections

    :param config: Configuration to sanitize
    :return: Sanitized configuration
    """
    return {k: v for k, v in config.items() if v in [0, False] or v}


def apply_config_part(base_config: Config, new_config_part: Config) -> Config:
    """
    Apply new part of static configuration. Used internally.

    :param base_config: Base configuration
    :param new_config_part: Changes to apply
    :return: Merged configuration
    """
    config = dict(base_config)
    for k, v in new_config_part.items():
        if k not in config:
            config[k] = v
        elif config[k] == v:
            continue
        elif isinstance(config[k], list):
            for el in v:
                if el not in config[k]:
                    config[k] = config[k] + [el]
        else:
            raise RuntimeError(
                f"Extractor tries to override '{config[k]}' "
                f"value of '{k}' with '{v}'",
            )
    return config
