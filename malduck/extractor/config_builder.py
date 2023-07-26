from typing import TYPE_CHECKING, Any, Dict, List, Optional

from maco.model import CategoryEnum, ConnUsageEnum, ExtractorModel

if TYPE_CHECKING:
    from .extractor import Extractor


class ConfigBuilder:
    """
    Allows to build configuration imperatively, using
    Maco model https://github.com/CybercentreCanada/Maco

    .. versionadded:: 4.4.0
    """

    def __init__(self, parent: "Extractor") -> None:
        self.parent = parent

    def push_config(self, config: Dict[str, Any], exclude_family=True) -> None:
        """
        Pushes Maco-compatible configuration part to the extraction context.

        :param config: Configuration part
        :param exclude_family: |
            By default 'family' is excluded because family match
            is determined by extraction method (e.g. if it's decorated with
            ``@weak``, it doesn't indicate a match).
            If you actually want to indicate a match and ignore that decorator,
            set exclude_family to False.
        """
        # 'family' is required field in ExtractorModel
        # In our case 'family' is indicator that family has been actually matched
        # which is determined by returned value from extractor method
        config = ExtractorModel.parse_obj(
            {**config, "family": self.parent.family}
        ).dict(
            exclude_defaults=True,
            exclude={
                "family",
            }
            if exclude_family
            else set(),
        )
        self.parent.push_config(config, jsonable=False)

    def add_other(self, others: Dict[str, Any]) -> None:
        """
        Add new fields to ``others`` key that doesn't match to any of
        predefined categories.

        ``others`` is merged similarly to configuration itself:

        - list elements are treated like ordered sets and
          are collecting all elements within extraction
        - other elements can be set only once, override will
          throw an exception

        :param others: Dictionary with other configuration fields
        """
        return self.push_config(dict(others=others))

    def set_version(self, version: str) -> None:
        """
        Sets malware version
        """
        return self.push_config(dict(version=version))

    def add_category(self, *category: CategoryEnum) -> None:
        """
        Adds malware category e.g. apt, keylogger etc.
        """
        return self.push_config(dict(category=category))

    def add_attack_ref(self, *attack_ref: str) -> None:
        """
        MITRE ATT&CK reference ids, e.g. 'T1129'.
        """
        return self.push_config(dict(attack=attack_ref))

    def add_capability_enabled(self, *capability_enabled: str) -> None:
        """
        Capabilities of the malware that are enabled.
        """
        return self.push_config(dict(capability_enabled=capability_enabled))

    def add_capability_disabled(self, *capability_disabled: str) -> None:
        """
        Capabilities of the malware that are disabled.
        """
        return self.push_config(dict(capability_disabled=capability_disabled))

    def add_campaign_id(self, *campaign_id: str) -> None:
        """
        Server/campaign id for malware.
        """
        return self.push_config(dict(campaign_id=campaign_id))

    def add_identifier(self, *identifier: str) -> None:
        """
        UUID/Identifiers for deployed instance of malware.
        """
        return self.push_config(dict(identifier=identifier))

    def add_decoded_strings(self, *string: str) -> None:
        """
        Decoded string from within malware.

        Usually there is a lot of strings so contents of this field
        might be put in separate object during further processing.
        """
        return self.push_config(dict(decoded_strings=string))

    def add_password(self, *password: str) -> None:
        """
        Any password extracted from the binary
        """
        return self.push_config(dict(password=password))

    def add_mutex(self, *mutex: str) -> None:
        """
        Mutex to prevent multiple instances
        """
        return self.push_config(dict(mutex=mutex))

    def add_pipe(self, *pipe: str) -> None:
        """
        Pipe name used for communication
        """
        return self.push_config(dict(pipe=pipe))

    def set_sleep_delay(self, sleep_delay: int) -> None:
        """
        Time to sleep/delay execution
        """
        return self.push_config(dict(sleep_delay=sleep_delay))

    def add_inject_exe(self, *inject_exe: str) -> None:
        """
        Name of executable to inject into
        """
        return self.push_config(dict(inject_exe=inject_exe))

    def add_binary(
        self,
        filename: str,
        data: bytes,
        datatype: Optional[ExtractorModel.Binary.TypeEnum] = None,
        encryption: Optional[ExtractorModel.Binary.Encryption] = None,
        other: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Extracted binary data e.g. additional files.

        :param filename: Name that identifies a file
        :param data: Contents of the binary
        :param datatype: Type of the binary
        :param encryption: Encryption used to protect the binary
        :param other: Other metadata

        .. note::

            ``filename`` is not a field of Maco model but it's usually necessary to
            identify binary, so we decided to make it required. Value of this field
            will be put in "other".
        """
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
        """
        FTP connection used by malware

        :param username: FTP username
        :param password: FTP password
        :param hostname: FTP hostname
        :param port: FTP port
        :param path: FTP path
        :param usage: Purpose of the connection
        """
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
        usage: Optional[ConnUsageEnum] = None,
    ) -> None:
        """
        SMTP connection used by malware

        :param username: SMTP username
        :param password: SMTP password
        :param hostname: SMTP hostname
        :param port: SMTP port
        :param mail_to: E-mail addresses used by attacker to receive data
        :param mail_from: E-mail address used by malware to send data
        :param subject: E-mail subject
        :param usage: Purpose of the connection
        """
        smtp = ExtractorModel.SMTP(
            username=username,
            password=password,
            hostname=hostname,
            port=port,
            mail_to=mail_to or [],
            mail_from=mail_from,
            subject=subject,
            usage=usage,
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
        """
        HTTP connection used by malware

        :param uri: |
            HTTP(S) URI contained in configuration. If you're able to parse it, it's preferred to use
            more detailed fields instead.

        :param protocol: URI scheme (usually 'http' or 'https')
        :param username: Username (e.g. for Basic auth)
        :param password: Password
        :param hostname: URI hostname
        :param port: Port (if custom or provided explicitly in malware)
        :param path: URI path
        :param query: URI query (part that follows the '?')
        :param fragment: URI fragment (part that follows the '#')
        :param user_agent: Custom User-Agent header used for communication
        :param method: HTTP method (GET/POST/...)
        :param headers: Dictionary with additional headers required to contact C&C
        :param max_size: Maximum accepted size by server
        :param usage: Purpose of the connection
        """
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
        """
        SSH connection used by malware

        :param username: Username
        :param password: Password
        :param hostname: Server hostname
        :param port: Port (if custom or provided explicitly in malware)
        :param usage: Purpose of the connection
        """
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
        """
        Proxy connection used by malware

        :param protocol: Proxy protocol (e.g. socks5)
        :param username: Proxy username
        :param password: Proxy password
        :param hostname: Server hostname
        :param port: Port (if custom or provided explicitly in malware)
        :param usage: Purpose of the connection
        """
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
        """
        DNS connection used by malware

        :param ip: IP of DNS server
        :param port: Port (if custom or provided explicitly in malware)
        :param usage: Purpose of the connection
        """
        dns = ExtractorModel.DNS(
            ip=ip,
            port=port,
            usage=usage,
        )
        return self.push_config(dict(dns=[dns]))

    def add_tcp(
        self,
        server_ip: Optional[str] = None,
        server_domain: Optional[str] = None,
        server_port: Optional[int] = None,
        client_ip: Optional[str] = None,
        client_port: Optional[int] = None,
        usage: Optional[ConnUsageEnum] = None,
    ) -> None:
        """
        TCP connection used by malware

        :param server_ip: IP of the server
        :param server_domain: Domain name of the server
        :param server_port: Port of the server
        :param client_ip: IP of the client (if set explicitly)
        :param client_port: Port of the client (if set explicitly)
        :param usage: Purpose of the connection
        """
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
        server_ip: Optional[str] = None,
        server_domain: Optional[str] = None,
        server_port: Optional[int] = None,
        client_ip: Optional[str] = None,
        client_port: Optional[int] = None,
        usage: Optional[ConnUsageEnum] = None,
    ) -> None:
        """
        UDP connection used by malware

        :param server_ip: IP of the server
        :param server_domain: Domain name of the server
        :param server_port: Port of the server
        :param client_ip: IP of the client (if set explicitly)
        :param client_port: Port of the client (if set explicitly)
        :param usage: Purpose of the connection
        """
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
        """
        Encryption used by malware

        :param algorithm: Encryption algorithm e.g. 'aes', 'xor', 'rc4' etc.
        :param public_key: Public key
        :param key: (Private) key.
        :param provider: Encryption library that is used (e.g. 'openssl')
        :param mode: Encryption mode e.g 'cbc'
        :param iv: Initialization vector
        :param seed: Seed for key generation
        :param nonce: Nonce
        :param constants: Encryption constants (e.g. custom algorithm constants, constants used for key derivation)
        :param usage: Purpose of encryption
        """
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
        dll: Optional[str] = None,
        name: Optional[str] = None,
        display_name: Optional[str] = None,
        description: Optional[str] = None,
    ):
        """
        Service set by malware

        :param dll: DLL that the service is loaded from
        :param name: Service/driver name for persistence
        :param display_name: Display name for service
        :param description: Description for service
        """
        service = ExtractorModel.Service(
            dll=dll, name=name, display_name=display_name, description=description
        )
        return self.push_config(dict(service=[service]))

    def add_cryptocurrency(
        self,
        coin: Optional[str] = None,
        address: Optional[str] = None,
        ransom_amount: Optional[float] = None,
        usage: Optional[ExtractorModel.Cryptocurrency.UsageEnum] = None,
    ) -> None:
        """
        Cryptocurrency used by malware

        :param coin: Coin used (e.g. BTC, ETH, USDT, BNB)
        :param address: Wallet address
        :param ransom_amount: Number of coins required (if hardcoded)
        :param usage: Purpose of cryptocurrency usage
        """
        cryptocurrency = ExtractorModel.Service(
            coin=coin, address=address, ransom_amount=ransom_amount, usage=usage
        )
        return self.push_config(dict(cryptocurrency=[cryptocurrency]))

    def add_path(
        self,
        path: str,
        usage: Optional[ExtractorModel.Path.UsageEnum] = None,
    ) -> None:
        """
        Storage path (UNC or local file system)

        :param path: Path
        :param usage: Purpose of the path
        """
        path_obj = ExtractorModel.Path(path=path, usage=usage)
        return self.push_config(dict(path=[path_obj]))

    def add_registry(
        self,
        key: str,
        usage: Optional[ExtractorModel.Registry.UsageEnum] = None,
    ) -> None:
        """
        Registry key

        :param key: Registry key
        :param usage: Purpose of the registry key
        """
        registry = ExtractorModel.Registry(
            key=key,
            usage=usage,
        )
        return self.push_config(dict(registry=[registry]))
