import logging
from collections import UserDict
from typing import TYPE_CHECKING, Any, Dict

log = logging.getLogger(__name__)

Config = Dict[str, Any]

if TYPE_CHECKING:
    ConfigSetDict = UserDict[str, Config]
else:
    ConfigSetDict = UserDict


class ConfigSet(ConfigSetDict):
    def push_partial_config(self, config: Config, family: str) -> None:
        """
        Pushes partial config part from extractor module to collection
        """
        if family not in self.data:
            self.data[family] = config
        else:
            self.data[family] = merge_configs(self.data[family], config)

    def merge_config_sets(self, new_configs: "ConfigSet") -> "ConfigSet":
        """
        Merges final config sets from different ProcessMemory extractions
        """
        config_set = dict(self.data)
        for family, config in new_configs.items():
            if family not in config_set:
                config_set[family] = config
            else:
                base_config = config_set[family]
                if is_config_better(base_config, config):
                    config_set[family] = config
                    log.debug("%s config looks better", family)
                else:
                    log.debug("%s config doesn't look better", family)
        return ConfigSet(config_set)

    def filter_final_configs(self) -> "ConfigSet":
        """
        Filters configs without "family" set (not indicating final extraction)
        """
        return ConfigSet(
            {
                family: config
                for family, config in self.data.items()
                if "family" in config
            }
        )

    def __repr__(self) -> str:
        return f"ConfigSet([{', '.join(self.data.keys())}])"


def is_config_better(base_config: Config, new_config: Config) -> bool:
    """
    Checks whether new config looks more reliable than base.
    Currently just checking the amount of non-empty keys.
    """
    base = [(k, v) for k, v in base_config.items() if v]
    new = [(k, v) for k, v in new_config.items() if v]
    return len(new) > len(base)


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


def merge_configs(base_config: Config, new_config: Config) -> Config:
    """
    Merge static configurations.

    :param base_config: Base configuration
    :param new_config: Changes to apply
    :return: Merged configuration
    """
    config = dict(base_config)
    for k, v in new_config.items():
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
                f"value of '{k}' with '{v}'"
            )
    return config
