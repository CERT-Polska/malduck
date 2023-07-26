from typing import Any, Dict

from maco.model import CategoryEnum, ExtractorModel

from .extractor import Extractor


class ConfigBuilder:
    def __init__(self, parent: Extractor):
        self.parent = parent

    def push_config(self, config: Dict[str, Any]):
        # 'family' is required field in ExtractorModel
        # In our case 'family' is indicator that family has been actually matched
        # which is determined by returned value from extractor method
        config = ExtractorModel.parse_obj(
            {**config, "family": self.parent.family}
        ).dict(
            exclude_unset=True,
            exclude={
                "family",
            },
        )
        self.parent.push_config(config)

    def add_others(self, others: Dict[str, Any]):
        return self.push_config(dict(others=others))

    def set_version(self, version: str):
        return self.push_config(dict(version=version))

    def add_category(self, *category: CategoryEnum):
        return self.push_config(dict(category=category))

    def add_attack_ref(self, *attack_refs: str):
        return self.push_config(dict(attack=attack_refs))

    def add_capability_enabled(self, *capability_enabled: str):
        return self.push_config(dict(capability_enabled=capability_enabled))

    def add_capability_disabled(self, *capability_disabled: str):
        return self.push_config(dict(capability_disabled=capability_disabled))

    def add_campaign_id(self, *campaign_id: str):
        return self.push_config(dict(campaign_id=campaign_id))

    def add_identifier(self, *identifier: str):
        return self.push_config(dict(identifier=identifier))

    def add_password(self, *password: str):
        return self.push_config(dict(password=password))

    def add_mutex(self, *mutex: str):
        return self.push_config(dict(mutex=mutex))

    def add_pipe(self, *pipe: str):
        return self.push_config(dict(pipe=pipe))

    def set_sleep_delay(self, sleep_delay: int):
        return self.push_config(dict(sleep_delay=sleep_delay))

    def add_inject_exe(self, *inject_exe: str):
        return self.push_config(dict(inject_exe=inject_exe))

    def add_binary(self, *binary: ExtractorModel.Binary):
        return self.push_config(dict(binaries=binary))

    def add_ftp(self, *ftp: ExtractorModel.FTP):
        return self.push_config(dict(ftp=ftp))

    def add_smtp(self, *smtp: ExtractorModel.SMTP):
        return self.push_config(dict(smtp=smtp))

    def add_http(self, *http: ExtractorModel.Http):
        return self.push_config(dict(http=http))

    def add_ssh(self, *ssh: ExtractorModel.SSH):
        return self.push_config(dict(ssh=ssh))

    def add_proxy(self, *proxy: ExtractorModel.Proxy):
        return self.push_config(dict(proxy=proxy))

    def add_dns(self, *dns: ExtractorModel.DNS):
        return self.push_config(dict(proxy=dns))

    def add_tcp(self, *tcp: ExtractorModel.Connection):
        return self.push_config(dict(tcp=tcp))

    def add_udp(self, *udp: ExtractorModel.Connection):
        return self.push_config(dict(udp=udp))

    def add_encryption(self, *encryption: ExtractorModel.Encryption):
        return self.push_config(dict(encryption=encryption))

    def add_cryptocurrency(self, *cryptocurrency: ExtractorModel.Cryptocurrency):
        return self.push_config(dict(cryptocurrency=cryptocurrency))

    def add_path(self, *path: ExtractorModel.Path):
        return self.push_config(dict(path=path))

    def add_registry(self, *registry: ExtractorModel.Registry):
        return self.push_config(dict(registry=registry))
