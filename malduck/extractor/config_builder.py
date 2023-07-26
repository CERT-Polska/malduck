from typing import Any, Dict, List, Optional

from maco.model import CategoryEnum, ConnUsageEnum, ExtractorModel

from .extractor import Extractor


class ConfigBuilder:
    """
    Allows to build configuration imperatively, using
    Maco model https://github.com/CybercentreCanada/Maco

    .. versionadded:: 4.4.0
    """
    def __init__(self, parent: Extractor) -> None:
        self.parent = parent

    def push_config(self, config: Dict[str, Any]) -> None:
        # 'family' is required field in ExtractorModel
        # In our case 'family' is indicator that family has been actually matched
        # which is determined by returned value from extractor method
        config = ExtractorModel.parse_obj(
            {**config, "family": self.parent.family}
        ).dict(
            exclude_defaults=True,
            exclude={
                "family",
            },
        )
        self.parent.push_config(config, jsonable=False)

    def add_other(self, others: Dict[str, Any]) -> None:
        return self.push_config(dict(others=others))

    def set_version(self, version: str) -> None:
        return self.push_config(dict(version=version))

    def add_category(self, *category: CategoryEnum) -> None:
        return self.push_config(dict(category=category))

    def add_attack_ref(self, *attack_ref: str) -> None:
        return self.push_config(dict(attack=attack_ref))

    def add_capability_enabled(self, *capability_enabled: str) -> None:
        return self.push_config(dict(capability_enabled=capability_enabled))

    def add_capability_disabled(self, *capability_disabled: str) -> None:
        return self.push_config(dict(capability_disabled=capability_disabled))

    def add_campaign_id(self, *campaign_id: str) -> None:
        return self.push_config(dict(campaign_id=campaign_id))

    def add_decoded_strings(self, *string: str) -> None:
        return self.push_config(dict(decoded_strings=string))

    def add_identifier(self, *identifier: str) -> None:
        return self.push_config(dict(identifier=identifier))

    def add_password(self, *password: str) -> None:
        return self.push_config(dict(password=password))

    def add_mutex(self, *mutex: str) -> None:
        return self.push_config(dict(mutex=mutex))

    def add_pipe(self, *pipe: str) -> None:
        return self.push_config(dict(pipe=pipe))

    def set_sleep_delay(self, sleep_delay: int) -> None:
        return self.push_config(dict(sleep_delay=sleep_delay))

    def add_inject_exe(self, *inject_exe: str) -> None:
        return self.push_config(dict(inject_exe=inject_exe))

    def add_binary(
        self,
        filename: str,
        data: bytes,
        datatype: Optional[ExtractorModel.Binary.TypeEnum] = None,
        encryption: Optional[ExtractorModel.Binary.Encryption] = None,
        other: Optional[Dict[str, Any]] = None,
    ) -> None:
        binary = ExtractorModel.Binary(
            data=data,
            datatype=datatype,
            encryption=encryption,
            other={**(other or {}), "filename": filename},
        )
        return self.push_config(dict(binaries=[binary]))

    def add_ftp(
        self,
        username: Optional[str] = None,
        password: Optional[str] = None,
        hostname: Optional[str] = None,
        port: Optional[int] = None,
        path: Optional[str] = None,
        usage: Optional[ConnUsageEnum] = None,
    ) -> None:
        ftp = ExtractorModel.FTP(
            username=username,
            password=password,
            hostname=hostname,
            port=port,
            path=path,
            usage=usage,
        )
        return self.push_config(dict(ftp=[ftp]))

    def add_smtp(
        self,
        username: Optional[str] = None,
        password: Optional[str] = None,
        hostname: Optional[str] = None,
        port: Optional[int] = None,
        mail_to: Optional[List[str]] = None,
        mail_from: Optional[str] = None,
        subject: Optional[str] = None,
    ) -> None:
        smtp = ExtractorModel.SMTP(
            username=username,
            password=password,
            hostname=hostname,
            port=port,
            mail_to=mail_to or [],
            mail_from=mail_from,
            subject=subject,
        )
        return self.push_config(dict(smtp=[smtp]))

    def add_http(
        self,
        uri: Optional[str] = None,
        protocol: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        hostname: Optional[str] = None,
        port: Optional[int] = None,
        path: Optional[str] = None,
        query: Optional[str] = None,
        fragment: Optional[str] = None,
        user_agent: Optional[str] = None,
        method: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        max_size: Optional[int] = None,
        usage: Optional[ConnUsageEnum] = None,
    ) -> None:
        http = ExtractorModel.Http(
            uri=uri,
            protocol=protocol,
            username=username,
            password=password,
            hostname=hostname,
            port=port,
            path=path,
            query=query,
            fragment=fragment,
            user_agent=user_agent,
            method=method,
            headers=headers,
            max_size=max_size,
            usage=usage,
        )
        return self.push_config(dict(http=[http]))

    def add_ssh(
        self,
        username: Optional[str] = None,
        password: Optional[str] = None,
        hostname: Optional[str] = None,
        port: Optional[int] = None,
        usage: Optional[ConnUsageEnum] = None,
    ) -> None:
        ssh = ExtractorModel.SSH(
            username=username,
            password=password,
            hostname=hostname,
            port=port,
            usage=usage,
        )
        return self.push_config(dict(ssh=[ssh]))

    def add_proxy(
        self,
        protocol: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        hostname: Optional[str] = None,
        port: Optional[int] = None,
        usage: Optional[ConnUsageEnum] = None,
    ) -> None:
        proxy = ExtractorModel.Proxy(
            protocol=protocol,
            username=username,
            password=password,
            hostname=hostname,
            port=port,
            usage=usage,
        )
        return self.push_config(dict(proxy=[proxy]))

    def add_dns(
        self,
        ip: Optional[str] = None,
        port: Optional[int] = None,
        usage: Optional[ConnUsageEnum] = None,
    ) -> None:
        dns = ExtractorModel.DNS(
            ip=ip,
            port=port,
            usage=usage,
        )
        return self.push_config(dict(dns=[dns]))

    def add_tcp(
        self,
        client_ip: Optional[str] = None,
        client_port: Optional[int] = None,
        server_ip: Optional[str] = None,
        server_domain: Optional[str] = None,
        server_port: Optional[int] = None,
        usage: Optional[ConnUsageEnum] = None,
    ) -> None:
        tcp = ExtractorModel.Connection(
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_domain=server_domain,
            server_port=server_port,
            usage=usage,
        )
        return self.push_config(dict(tcp=[tcp]))

    def add_udp(
        self,
        client_ip: Optional[str] = None,
        client_port: Optional[int] = None,
        server_ip: Optional[str] = None,
        server_domain: Optional[str] = None,
        server_port: Optional[int] = None,
        usage: Optional[ConnUsageEnum] = None,
    ) -> None:
        udp = ExtractorModel.Connection(
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_domain=server_domain,
            server_port=server_port,
            usage=usage,
        )
        return self.push_config(dict(udp=[udp]))

    def add_encryption(
        self,
        algorithm: Optional[str] = None,
        public_key: Optional[str] = None,
        key: Optional[str] = None,
        provider: Optional[str] = None,
        mode: Optional[str] = None,
        iv: Optional[str] = None,
        seed: Optional[str] = None,
        nonce: Optional[str] = None,
        constants: List[str] = None,
        usage: Optional[ExtractorModel.Encryption.UsageEnum] = None,
    ) -> None:
        encryption = ExtractorModel.Encryption(
            algorithm=algorithm,
            public_key=public_key,
            key=key,
            provider=provider,
            mode=mode,
            iv=iv,
            seed=seed,
            nonce=nonce,
            constants=constants or [],
            usage=usage,
        )
        return self.push_config(dict(encryption=[encryption]))

    def add_service(
        self,
        dll: Optional[str] = None,  # dll that the service is loaded from
        name: Optional[str] = None,  # service/driver name for persistence
        display_name: Optional[str] = None,  # display name for service
        description: Optional[str] = None,  # description for service
    ):
        service = ExtractorModel.Service(
            dll=dll, name=name, display_name=display_name, description=description
        )
        return self.push_config(dict(service=[service]))

    def add_cryptocurrency(
        self,
        coin: Optional[str] = None,  # BTC,ETH,USDT,BNB, etc
        address: Optional[str] = None,
        ransom_amount: Optional[
            float
        ] = None,  # number of coins required (if hardcoded)
        usage: Optional[ExtractorModel.Cryptocurrency.UsageEnum] = None,
    ) -> None:
        cryptocurrency = ExtractorModel.Service(
            coin=coin, address=address, ransom_amount=ransom_amount, usage=usage
        )
        return self.push_config(dict(cryptocurrency=[cryptocurrency]))

    def add_path(
        self,
        path: str,
        usage: Optional[ExtractorModel.Path.UsageEnum] = None,
    ) -> None:
        path_obj = ExtractorModel.Path(path=path, usage=usage)
        return self.push_config(dict(path=[path_obj]))

    def add_registry(
        self,
        key: str,
        usage: Optional[ExtractorModel.Registry.UsageEnum] = None,
    ) -> None:
        registry = ExtractorModel.Registry(
            key=key,
            usage=usage,
        )
        return self.push_config(dict(registry=[registry]))
