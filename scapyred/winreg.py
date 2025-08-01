"""
DCE/RPC client
"""

from dataclasses import dataclass
import socket
import os
import logging

from enum import IntEnum, IntFlag, StrEnum, Enum
from ctypes.wintypes import PFILETIME
from typing import Optional, NoReturn
from pathlib import PureWindowsPath

from scapy.themes import DefaultTheme
from scapy.base_classes import Net
from scapy.utils import (
    CLIUtil,
    valid_ip,
    valid_ip6,
)
from scapy.utils6 import Net6
from scapy.layers.kerberos import (
    KerberosSSP,
    krb_as_and_tgs,
    _parse_upn,
)
from scapy.layers.msrpce.rpcclient import DCERPC_Client
from scapy.layers.dcerpc import find_dcerpc_interface, DCERPC_Transport
from scapy.layers.ntlm import MD4le, NTLMSSP
from scapy.layers.spnego import SPNEGOSSP
from scapy.layers.smb2 import (
    SECURITY_DESCRIPTOR,
    WINNT_SID,
    WINNT_ACL,
    WINNT_ACE_HEADER,
    WINNT_ACCESS_ALLOWED_ACE,
)
from scapy.layers.dcerpc import (
    RPC_C_AUTHN_LEVEL,
    NDRConformantArray,
    NDRPointer,
    NDRVaryingArray,
)
from scapy.config import conf

# pylint: disable-next=too-many-function-args
conf.exts.load("scapy-rpc")
conf.color_theme = DefaultTheme()

# pylint: disable-next=import-error, no-name-in-module, wrong-import-position
from scapy.layers.msrpce.raw.ms_rrp import (
    OpenClassesRoot_Request,
    OpenLocalMachine_Request,
    OpenCurrentUser_Request,
    OpenUsers_Request,
    OpenCurrentConfig_Request,
    OpenPerformanceData_Request,
    OpenPerformanceText_Request,
    OpenPerformanceNlsText_Request,
    BaseRegOpenKey_Request,
    BaseRegEnumKey_Request,
    BaseRegEnumValue_Request,
    BaseRegQueryValue_Request,
    BaseRegGetVersion_Request,
    BaseRegQueryInfoKey_Request,
    BaseRegGetKeySecurity_Request,
    BaseRegSaveKey_Request,
    PRPC_SECURITY_DESCRIPTOR,
    PRPC_SECURITY_ATTRIBUTES,
    RPC_SECURITY_DESCRIPTOR,
    NDRContextHandle,
    RPC_UNICODE_STRING,
)


logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s][%(funcName)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    filename="winreg.log",  # write logs here
    filemode="w",
)
logger = logging.getLogger(__name__)


class AccessRights(IntFlag):
    """
    Access rights for registry keys
    """

    # Access rights for registry keys
    # These constants are used to specify the access rights when opening or creating registry keys.
    KEY_QUERY_VALUE = 0x00000001
    KEY_ENUMERATE_SUB_KEYS = 0x00000008
    STANDARD_RIGHTS_READ = 0x00020000
    MAX_ALLOWED = 0x02000000
    FILE_ALL_ACCESS = 0x001F01FF


class RegOptions(IntFlag):
    """
    Registry options for registry keys
    """

    REG_OPTION_NON_VOLATILE = 0x00000000
    REG_OPTION_VOLATILE = 0x00000001
    REG_OPTION_CREATE_LINK = 0x00000002
    REG_OPTION_BACKUP_RESTORE = 0x00000004
    REG_OPTION_OPEN_LINK = 0x00000008
    REG_OPTION_DONT_VIRTUALIZE = 0x00000010


class ErrorCodes(IntEnum):
    """
    Error codes for registry operations
    """

    ERROR_SUCCESS = 0x00000000
    ERROR_ACCESS_DENIED = 0x00000005
    ERROR_FILE_NOT_FOUND = 0x00000002
    ERROR_INVALID_HANDLE = 0x00000006
    ERROR_NOT_SAME_DEVICE = 0x00000011
    ERROR_WRITE_PROTECT = 0x00000013
    ERROR_INVALID_PARAMETER = 0x00000057
    ERROR_CALL_NOT_IMPLEMENTED = 0x00000057
    ERROR_NO_MORE_ITEMS = 0x00000103
    ERROR_NOACCESS = 0x000003E6
    ERROR_SUBKEY_NOT_FOUND = 0x000006F7
    ERROR_INSUFFICIENT_BUFFER = 0x0000007A
    ERROR_MORE_DATA = 0x000000EA

    def __str__(self) -> str:
        """
        Return the string representation of the error code.
        :return: The string representation of the error code.
        """
        return self.name


class RootKeys(StrEnum):
    """
    Root keys for the Windows registry
    """

    # Registry root keys
    # These constants are used to specify the root keys of the Windows registry.
    # The root keys are the top-level keys in the registry hierarchy.

    # Registry entries subordinate to this key define types (or classes) of documents and the
    # properties associated with those types.
    # The subkeys of the HKEY_CLASSES_ROOT key are a merged view of the following two subkeys:
    HKEY_CLASSES_ROOT = "HKCROOT"

    # Registry entries subordinate to this key define the preferences of the current user.
    # These preferences include the settings of environment variables, data on program groups,
    # colors, printers, network connections, and application preferences.
    # The HKEY_CURRENT_USER root key is a subkey of the HKEY_USERS root key, as described in
    # section 3.1.1.8.
    HKEY_CURRENT_USER = "HKCU"

    # Registry entries subordinate to this key define the physical state of the computer,
    # including data on the bus type, system memory, and installed hardware and software.
    HKEY_LOCAL_MACHINE = "HKLM"

    # This key contains information on the current hardware profile of the local computer.
    # HKEY_CURRENT_CONFIG is an alias for
    # HKEY_LOCAL_MACHINE\System\CurrentControlSet\Hardware Profiles\Current
    HKEY_CURRENT_CONFIG = "HKC"

    # This key define the default user configuration for new users on the local computer and the
    # user configuration for the current user.
    HKEY_USERS = "HKU"

    # Registry entries subordinate to this key allow access to performance data.
    HKEY_PERFORMANCE_DATA = "HKPERFDATA"

    # Registry entries subordinate to this key reference the text strings that describe counters
    # in U.S. English.
    HKEY_PERFORMANCE_TEXT = "HKPERFTXT"

    # Registry entries subordinate to this key reference the text strings that describe
    # counters in the local language of the area in which the computer is running.
    HKEY_PERFORMANCE_NLSTEXT = "HKPERFNLSTXT"

    def __new__(cls, value):
        # 1. Strip and uppercase the raw input
        normalized = value.strip().upper()
        # 2. Create the enum member with the normalized value
        obj = str.__new__(cls, normalized)
        obj._value_ = normalized
        return obj


class RegType(IntEnum):
    """
    Registry value types
    """

    # Registry value types
    # These constants are used to specify the type of a registry value.
    REG_SZ = 1  # Unicode string
    REG_EXPAND_SZ = 2  # Unicode string with environment variable expansion
    REG_BINARY = 3  # Binary data
    REG_DWORD = 4  # 32-bit unsigned integer
    REG_DWORD_BIG_ENDIAN = 5  # 32-bit unsigned integer in big-endian format
    REG_LINK = 6  # Symbolic link
    REG_MULTI_SZ = 7  # Multiple Unicode strings
    REG_QWORD = 11  # 64-bit unsigned integer
    UNK = 99999  # fallback default

    @classmethod
    def _missing_(cls, value):
        print(f"Unknown registry type: {value}, using UNK")
        return cls.UNK


def from_filetime_to_datetime(lp_filetime: PFILETIME) -> str:
    """
    Convert a filetime to a human readable date
    """
    from datetime import datetime, timezone

    filetime = lp_filetime.dwLowDateTime + (lp_filetime.dwHighDateTime << 32)
    # Filetime is in 100ns intervals since 1601-01-01
    # Convert to seconds since epoch
    seconds = (filetime - 116444736000000000) // 10000000
    return datetime.fromtimestamp(seconds, tz=timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S"
    )


def is_status_ok(status: int) -> bool:
    """
    Check the error code and raise an exception if it is not successful.
    :param status: The error code to check.
    """
    try:
        err = ErrorCodes(status)
        if err not in [
            ErrorCodes.ERROR_SUCCESS,
            ErrorCodes.ERROR_NO_MORE_ITEMS,
            ErrorCodes.ERROR_MORE_DATA,
        ]:
            print(f"[!] Error: {hex(err.value)} - {ErrorCodes(status).name}")
            return False
        return True
    except ValueError as exc:
        print(f"[!] Error: {hex(status)} - Unknown error code")
        raise ValueError(f"Error: {hex(status)} - Unknown error code") from exc


AVAILABLE_ROOT_KEYS: list[str] = [
    RootKeys.HKEY_LOCAL_MACHINE,
    RootKeys.HKEY_CURRENT_USER,
    RootKeys.HKEY_USERS,
    RootKeys.HKEY_CLASSES_ROOT,
    RootKeys.HKEY_CURRENT_CONFIG,
    RootKeys.HKEY_PERFORMANCE_DATA,
    RootKeys.HKEY_PERFORMANCE_TEXT,
    RootKeys.HKEY_PERFORMANCE_NLSTEXT,
]

READ_ACCESS_RIGHTS = (
    AccessRights.KEY_QUERY_VALUE
    | AccessRights.KEY_ENUMERATE_SUB_KEYS
    | AccessRights.STANDARD_RIGHTS_READ
)


class WellKnownSIDs(Enum):
    """
    Well-known SIDs.
    """

    SY = WINNT_SID.fromstr("S-1-5-18")  # Local System
    BA = WINNT_SID.fromstr("S-1-5-32-544")  # Built-in Administrators


DEFAULT_SECURITY_DESCRIPTOR = SECURITY_DESCRIPTOR(
    Control=0x1000 | 0x8000 | 0x4,
    OwnerSid=WellKnownSIDs.SY.value,  # Local System SID
    GroupSid=WellKnownSIDs.SY.value,  # Local System SID
    DACL=WINNT_ACL(
        Aces=[
            WINNT_ACE_HEADER(
                AceType=0x0,  # ACCESS_ALLOWED_ACE_TYPE
                AceFlags=0x0,  # No flags
            )
            / WINNT_ACCESS_ALLOWED_ACE(
                Mask=0x00020000,  # Read access rights
                Sid=WellKnownSIDs.SY.value,  # Built-in Administrators SID
            ),
        ],
    ),
    ndr64=True,
)


class RegEntry:
    """
    RegEntry to properly parse the data based on the type.

        :param reg_value: the name of the registry value (str)
        :param reg_type: the type of the registry value (int)
        :param reg_data: the data of the registry value (str)
    """

    def __init__(self, reg_value: str, reg_type: int, reg_data: bytes):
        self.reg_value = reg_value
        try:
            self.reg_type = RegType(reg_type)
        except ValueError:
            self.reg_type = RegType.UNK

        match self.reg_type:
            case RegType.REG_MULTI_SZ | RegType.REG_SZ | RegType.REG_EXPAND_SZ:
                if self.reg_type == RegType.REG_MULTI_SZ:
                    # decode multiple null terminated strings
                    self.reg_data = reg_data.decode("utf-16le")[:-2].replace(
                        "\x00", "\n"
                    )
                else:
                    self.reg_data = reg_data.decode("utf-16le")

            case RegType.REG_BINARY:
                self.reg_data = reg_data

            case RegType.REG_DWORD | RegType.REG_QWORD:
                self.reg_data = int.from_bytes(reg_data, byteorder="little")

            case RegType.REG_DWORD_BIG_ENDIAN:
                self.reg_data = int.from_bytes(reg_data, byteorder="big")

            case RegType.REG_LINK:
                self.reg_data = reg_data.decode("utf-16le")

            case _:
                self.reg_data = reg_data

    def __str__(self) -> str:
        return f"{self.reg_value} ({self.reg_type.name}) {self.reg_data}"

    def __repr__(self) -> str:
        return f"RegEntry({self.reg_value}, {self.reg_type}, {self.reg_data})"


@dataclass
class CacheElt:
    """
    Cache element to store the handle and the subkey path
    """

    handle: NDRContextHandle
    access: AccessRights
    values: list


@conf.commands.register
class RegClient(CLIUtil):
    r"""
    A simple registry CLI

    :param target: can be a hostname, the IPv4 or the IPv6 to connect to
    :param UPN: the upn to use (DOMAIN/USER, DOMAIN\USER, USER@DOMAIN or USER)
    :param guest: use guest mode (over NTLM)
    :param ssp: if provided, use this SSP for auth.
    :param kerberos: if available, whether to use Kerberos or not
    :param kerberos_required: require kerberos
    :param port: the TCP port. default 445
    :param password: (string) if provided, used for auth
    :param HashNt: (bytes) if provided, used for auth (NTLM)
    :param ST: if provided, the service ticket to use (Kerberos)
    :param KEY: if provided, the session key associated to the ticket (Kerberos)
    :param cli: CLI mode (default True). False to use for scripting
    :param rootKey: the root key to get a handle to (HKLM, HKCU, etc.), in CLI mode you can chose it later
    :param subKey: the subkey to use (default None, in CLI mode you can chose it later)


    Some additional SMB parameters are available under help(SMB_Client). Some of
    them include the following:

    :param REQUIRE_ENCRYPTION: requires encryption.
    """

    def __init__(
        self,
        target: str,
        UPN: str = None,
        password: str = None,
        guest: bool = False,
        kerberos: bool = True,
        kerberos_required: bool = False,
        HashNt: str = None,
        port: int = 445,
        timeout: int = 2,
        debug: int = 0,
        ssp=None,
        ST=None,
        KEY=None,
        cli=True,
        rootKey: str = None,
        subKey: str = None,
        # SMB arguments
        **kwargs,
    ):
        if cli:
            self._depcheck()
        hostname = None
        # Check if target is a hostname / Check IP
        if ":" in target:
            family = socket.AF_INET6
            if not valid_ip6(target):
                hostname = target
            target = str(Net6(target))
        else:
            family = socket.AF_INET
            if not valid_ip(target):
                hostname = target
            target = str(Net(target))
        assert UPN or ssp or guest, "Either UPN, ssp or guest must be provided !"
        # Do we need to build a SSP?
        if ssp is None:
            # Create the SSP (only if not guest mode)
            if not guest:
                # Check UPN
                try:
                    _, realm = _parse_upn(UPN)
                    if realm == ".":
                        # Local
                        kerberos = False
                except ValueError:
                    # not a UPN: NTLM
                    kerberos = False
                # Do we need to ask the password?
                if HashNt is None and password is None and ST is None:
                    # yes.
                    from prompt_toolkit import prompt

                    password = prompt("Password: ", is_password=True)
                ssps = []
                # Kerberos
                if kerberos and hostname:
                    if ST is None:
                        resp = krb_as_and_tgs(
                            upn=UPN,
                            spn="cifs/%s" % hostname,
                            password=password,
                            debug=debug,
                        )
                        if resp is not None:
                            ST, KEY = resp.tgsrep.ticket, resp.sessionkey
                    if ST:
                        ssps.append(KerberosSSP(UPN=UPN, ST=ST, KEY=KEY, debug=debug))
                    elif kerberos_required:
                        raise ValueError(
                            "Kerberos required but target isn't a hostname !"
                        )
                elif kerberos_required:
                    raise ValueError(
                        "Kerberos required but domain not specified in the UPN, "
                        "or target isn't a hostname !"
                    )
                # NTLM
                if not kerberos_required:
                    if HashNt is None and password is not None:
                        HashNt = MD4le(password)
                    ssps.append(NTLMSSP(UPN=UPN, HASHNT=HashNt))
                # Build the SSP
                ssp = SPNEGOSSP(ssps)
            else:
                # Guest mode
                ssp = None

        # Interface WINREG
        self.interface = find_dcerpc_interface("winreg")

        # Connexion NCACN_NP: SMB
        self.client = DCERPC_Client(
            DCERPC_Transport.NCACN_NP,
            auth_level=RPC_C_AUTHN_LEVEL.PKT_PRIVACY,
            ssp=ssp,
            ndr64=True,
        )
        if debug:
            logger.setLevel(logging.DEBUG)
            logger.debug(
                "Connecting to %s:%d with UPN=%s, guest=%s, kerberos=%s, kerberos_required=%s",
                target,
                port,
                UPN,
                guest,
                kerberos,
                kerberos_required,
            )

        self.timeout = timeout
        self.client.verb = False
        try:
            self.client.connect(target)
            self.client.open_smbpipe("winreg")
        except ValueError as exc:
            if "3221225644" in str(exc):
                print(
                    "[!] Warn: Remote service didn't seem to be running. Let's try again now that we should have trigger it."
                )
                self.client.open_smbpipe("winreg")
            else:
                raise exc
        self.client.bind(self.interface)
        self.cache: dict[str : dict[str, CacheElt]] = {
            "ls": dict(),
            "cat": dict(),
            "cd": dict(),
        }
        # Options for registry operations default to non-volatile
        # This means that the registry key will not be deleted when the system is restarted.
        self.extra_options = RegOptions.REG_OPTION_NON_VOLATILE
        self.root_handle = {}
        self.current_root_handle = None
        self.current_subkey_handle = None
        self.current_subkey_path: PureWindowsPath = PureWindowsPath("")
        if rootKey in AVAILABLE_ROOT_KEYS:
            self.current_root_path = rootKey.strip()
            self.use(self.current_root_path)
        else:
            self.current_root_path = "CHOOSE ROOT KEY"
        if subKey:
            self.cd(subKey.strip())
        if cli:
            self.loop(debug=debug)

    def ps1(self) -> str:
        return f"[reg] {self.current_root_path}\\{self.current_subkey_path} > "

    @CLIUtil.addcommand()
    def close(self) -> NoReturn:
        """
        Close all connections
        """

        print("Connection closed")
        self.client.close()

    # --------------------------------------------- #
    #                   Use Root Key
    # --------------------------------------------- #

    @CLIUtil.addcommand()
    def use(self, root_path):
        """
        Selects and sets the base registry key (root) to use for subsequent operations.

        Parameters:
            root_path (str): The root registry path to use. Should start with one of the following:
                - HKEY_CLASSES_ROOT
                - HKEY_LOCAL_MACHINE
                - HKEY_CURRENT_USER

        Behavior:
            - Determines which registry root to use based on the prefix of `root_path`.
            - Opens the corresponding registry root handle if not already opened, using the appropriate request.
            - Sets `self.current_root_handle` and `self.current_root_path` to the selected root.
            - Clears the local subkey cache
            - Changes the current directory to the root of the selected registry hive.
        """

        default_read_access_rights = READ_ACCESS_RIGHTS
        root_path = RootKeys(root_path.upper().strip())

        match root_path:
            case RootKeys.HKEY_CLASSES_ROOT:
                # Change to HKCR root
                self.current_root_handle = self.root_handle.setdefault(
                    RootKeys.HKEY_CLASSES_ROOT.value,
                    self.client.sr1_req(
                        OpenClassesRoot_Request(
                            ServerName=None,
                            samDesired=default_read_access_rights,
                            ndr64=True,
                        ),
                        timeout=self.timeout,
                    ).phKey,
                )

            case RootKeys.HKEY_CURRENT_USER:
                # Change to HKCU root
                self.current_root_handle = self.root_handle.setdefault(
                    RootKeys.HKEY_CURRENT_USER.value,
                    self.client.sr1_req(
                        OpenCurrentUser_Request(
                            ServerName=None,
                            samDesired=default_read_access_rights,
                            ndr64=True,
                        ),
                        timeout=self.timeout,
                    ).phKey,
                )

            case RootKeys.HKEY_LOCAL_MACHINE:
                # Change to HKLM root
                self.current_root_handle = self.root_handle.setdefault(
                    RootKeys.HKEY_LOCAL_MACHINE.value,
                    self.client.sr1_req(
                        OpenLocalMachine_Request(
                            ServerName=None,
                            samDesired=default_read_access_rights,
                            ndr64=True,
                        ),
                        timeout=self.timeout,
                    ).phKey,
                )

            case RootKeys.HKEY_CURRENT_CONFIG:
                # Change to HKCU root
                self.current_root_handle = self.root_handle.setdefault(
                    RootKeys.HKEY_CURRENT_CONFIG.value,
                    self.client.sr1_req(
                        OpenCurrentConfig_Request(
                            ServerName=None,
                            samDesired=default_read_access_rights,
                            ndr64=True,
                        ),
                        timeout=self.timeout,
                    ).phKey,
                )

            case RootKeys.HKEY_USERS:
                self.current_root_handle = self.root_handle.setdefault(
                    RootKeys.HKEY_USERS.value,
                    self.client.sr1_req(
                        OpenUsers_Request(
                            ServerName=None,
                            samDesired=default_read_access_rights,
                            ndr64=True,
                        ),
                        timeout=self.timeout,
                    ).phKey,
                )

            case RootKeys.HKEY_PERFORMANCE_DATA:
                self.current_root_handle = self.root_handle.setdefault(
                    RootKeys.HKEY_PERFORMANCE_DATA.value,
                    self.client.sr1_req(
                        OpenPerformanceData_Request(
                            ServerName=None,
                            samDesired=default_read_access_rights,
                            ndr64=True,
                        ),
                        timeout=self.timeout,
                    ).phKey,
                )

            case RootKeys.HKEY_PERFORMANCE_TEXT:
                self.current_root_handle = self.root_handle.setdefault(
                    RootKeys.HKEY_PERFORMANCE_TEXT.value,
                    self.client.sr1_req(
                        OpenPerformanceText_Request(
                            ServerName=None,
                            samDesired=default_read_access_rights,
                            ndr64=True,
                        ),
                        timeout=self.timeout,
                    ).phKey,
                )

            case RootKeys.HKEY_PERFORMANCE_NLSTEXT:
                self.current_root_handle = self.root_handle.setdefault(
                    RootKeys.HKEY_PERFORMANCE_NLSTEXT.value,
                    self.client.sr1_req(
                        OpenPerformanceNlsText_Request(
                            ServerName=None,
                            samDesired=default_read_access_rights,
                            ndr64=True,
                        ),
                        timeout=self.timeout,
                    ).phKey,
                )

            case _:
                # If the root key is not recognized, raise an error
                print(f"Unknown root key: {root_path}")
                self._clear_all_caches()
                self.current_root_handle = None
                self.current_root_path = "CHOOSE ROOT KEY"
                self.cd("")
                return

        self.current_root_path = root_path.value
        self._clear_all_caches()
        self.cd("")

    @CLIUtil.addcomplete(use)
    def use_complete(self, root_key: str) -> list[str]:
        """
        Auto complete root key for `use`
        """
        return [
            str(rkey)
            for rkey in AVAILABLE_ROOT_KEYS
            if str(rkey).lower().startswith(root_key.lower())
        ]

    # --------------------------------------------- #
    #                   List and Cat
    # --------------------------------------------- #
    @CLIUtil.addcommand(spaces=True)
    def ls(self, folder: Optional[str] = None) -> list[str]:
        """
        EnumKeys of the current subkey path
        """

        res = self._get_cached_elt(folder=folder, cache_name="ls")
        if res is None:
            return []
        elif len(res.values) != 0:
            # If the resolution was already performed,
            # no need to query again the RPC
            return res.values

        if folder is None:
            folder = ""

        subkey_path = self._join_path(self.current_subkey_path, folder)

        idx = 0
        while True:
            req = BaseRegEnumKey_Request(
                hKey=res.handle,
                dwIndex=idx,
                lpNameIn=RPC_UNICODE_STRING(MaximumLength=1024),
                lpClassIn=RPC_UNICODE_STRING(),
                lpftLastWriteTime=None,
                ndr64=True,
            )

            resp = self.client.sr1_req(req)
            if resp.status == ErrorCodes.ERROR_NO_MORE_ITEMS:
                break
            elif not is_status_ok(resp.status):
                print(
                    f"[-] Error : got status {hex(resp.status)} while enumerating keys"
                )
                self.cache["ls"].pop(subkey_path, None)
                return []

            self.cache["ls"][subkey_path].values.append(
                resp.lpNameOut.valueof("Buffer").decode("utf-8").strip("\x00")
            )
            idx += 1

        return self.cache["ls"][subkey_path].values

    @CLIUtil.addoutput(ls)
    def ls_output(self, results: list[str]) -> NoReturn:
        """
        Print the output of 'ls'
        """
        for subkey in results:
            print(subkey)

    @CLIUtil.addcomplete(ls)
    def ls_complete(self, folder: str) -> list[str]:
        """
        Auto-complete ls
        """
        if self._require_root_handles(silent=True):
            return []
        return [
            str(subk)
            for subk in self.ls()
            if str(subk).lower().startswith(folder.lower())
        ]

    @CLIUtil.addcommand(spaces=True)
    def cat(self, folder: Optional[str] = None) -> list[tuple[str, str]]:
        """
        Enumerates and retrieves registry values for a given subkey path.

        If no folder is specified, uses the current subkey path and caches results to avoid redundant RPC queries.
        Otherwise, enumerates values under the specified folder path.

        Args:
            folder (Optional[str]): The subkey path to enumerate. If None or empty, uses the current subkey path.

        Returns:
            list[tuple[str, str]]: A list of registry entries (as RegEntry objects) for the specified subkey path.
                                   Returns an empty list if the handle is invalid or an error occurs during enumeration.

        Side Effects:
            - May print error messages to standard output if RPC queries fail.
            - Updates internal cache for previously enumerated subkey paths.
        """
        res = self._get_cached_elt(folder=folder, cache_name="cat")
        if res is None:
            return []
        elif len(res.values) != 0:
            # If the resolution was already performed,
            # no need to query again the RPC
            return res.values

        subkey_path = self._join_path(self.current_subkey_path, folder)

        idx = 0
        while True:
            # Get the name of the value at index idx
            req = BaseRegEnumValue_Request(
                hKey=res.handle,
                dwIndex=idx,
                lpValueNameIn=RPC_UNICODE_STRING(
                    MaximumLength=2048,
                    Buffer=NDRPointer(
                        value=NDRConformantArray(
                            max_count=1024, value=NDRVaryingArray(value=b"")
                        )
                    ),
                ),
                lpType=0,  # pointer to type, set to 0 for query
                lpData=None,  # pointer to buffer
                lpcbData=0,  # pointer to buffer size
                lpcbLen=0,  # pointer to length
                ndr64=True,
            )

            resp = self.client.sr1_req(req)
            if resp.status == ErrorCodes.ERROR_NO_MORE_ITEMS:
                break
            elif not is_status_ok(resp.status):
                print(
                    f"[-] Error : got status {hex(resp.status)} while enumerating values"
                )
                self.cache["cat"].pop(subkey_path, None)
                return []

            # Get the value name and type
            # for the name we got earlier
            req = BaseRegQueryValue_Request(
                hKey=res.handle,
                lpValueName=resp.valueof("lpValueNameOut"),
                lpType=0,
                lpcbData=1024,
                lpcbLen=0,
                lpData=NDRPointer(
                    value=NDRConformantArray(
                        max_count=1024, value=NDRVaryingArray(actual_count=0, value=b"")
                    )
                ),
                ndr64=True,
            )

            resp2 = self.client.sr1_req(req)
            if resp2.status == ErrorCodes.ERROR_MORE_DATA:
                # The buffer was too small, we need to retry with a larger one
                req.lpcbData = resp2.lpcbData
                req.lpData.value.max_count = resp2.lpcbData.value
                resp2 = self.client.sr1_req(req)

            if not is_status_ok(resp2.status):
                print(
                    f"[-] Error : got status {hex(resp2.status)} while querying value"
                )
                self.cache["cat"].pop(subkey_path, None)
                return []

            value = (
                resp.valueof("lpValueNameOut").valueof("Buffer").decode("utf-8").strip()
            )
            self.cache["cat"][subkey_path].values.append(
                RegEntry(
                    reg_value=value,
                    reg_type=resp2.valueof("lpType"),
                    reg_data=resp2.valueof("lpData"),
                )
            )

            idx += 1

        return self.cache["cat"][subkey_path].values

    @CLIUtil.addoutput(cat)
    def cat_output(self, results: list[RegEntry]) -> None:
        """
        Print the output of 'cat'
        """
        if not results or len(results) == 0:
            print("No values found.")
            return

        for entry in results:
            print(
                f"  - {entry.reg_value:<20} {'(' + entry.reg_type.name + ')':<15} {entry.reg_data}"
            )

    @CLIUtil.addcomplete(cat)
    def cat_complete(self, folder: str) -> list[str]:
        """
        Auto-complete cat
        """
        if self._require_root_handles(silent=True):
            return []
        return [
            str(subk)
            for subk in self.ls()
            if str(subk).lower().startswith(folder.lower())
        ]

    # --------------------------------------------- #
    #                   Change Directory
    # --------------------------------------------- #

    @CLIUtil.addcommand(spaces=True)
    def cd(self, subkey: str) -> None:
        """
        Change current subkey path
        """
        if subkey.strip() == "":
            # If the subkey is ".", we do not change the current subkey path
            tmp_path = PureWindowsPath()
            tmp_handle = self.get_handle_on_subkey(tmp_path)

        else:
            res = self._get_cached_elt(
                folder=subkey,
                cache_name="cd",
            )
            tmp_handle = res.handle if res else None
            tmp_path = self._join_path(self.current_subkey_path, subkey)

        if tmp_handle is not None:
            # If the handle was successfully retrieved,
            # we update the current subkey path and handle
            self.current_subkey_path = tmp_path
            self.current_subkey_handle = tmp_handle

    @CLIUtil.addcomplete(cd)
    def cd_complete(self, folder: str) -> list[str]:
        """
        Auto-complete cd
        """
        if self._require_root_handles(silent=True):
            return []
        return [
            str(subk)
            for subk in self.ls()
            if str(subk).lower().startswith(folder.lower())
        ]

    # --------------------------------------------- #
    #                   Get Information
    # --------------------------------------------- #

    @CLIUtil.addcommand()
    def get_sd(self, folder: Optional[str] = None) -> Optional[SECURITY_DESCRIPTOR]:
        """
        Get the security descriptor of the current subkey. SACL are not retrieve at this point (TODO).

        """
        handle = self._get_cached_elt(folder=folder)
        if handle is None:
            return None

        req = BaseRegGetKeySecurity_Request(
            hKey=handle,
            SecurityInformation=0x00000001  # OWNER_SECURITY_INFORMATION
            | 0x00000002  # GROUP_SECURITY_INFORMATION
            | 0x00000004,  # DACL_SECURITY_INFORMATION
            pRpcSecurityDescriptorIn=PRPC_SECURITY_DESCRIPTOR(
                cbInSecurityDescriptor=512,  # Initial size of the buffer
            ),
            ndr64=True,
        )

        resp = self.client.sr1_req(req)
        if resp.status == ErrorCodes.ERROR_INSUFFICIENT_BUFFER:
            # The buffer was too small, we need to retry with a larger one
            req.pRpcSecurityDescriptorIn.cbInSecurityDescriptor = (
                resp.pRpcSecurityDescriptorOut.cbInSecurityDescriptor
            )
            resp = self.client.sr1_req(req)

        if not is_status_ok(resp.status):
            print(f"[-] Error : got status {hex(resp.status)} while getting security")
            return None

        results = resp.pRpcSecurityDescriptorOut.valueof("lpSecurityDescriptor")
        sd = SECURITY_DESCRIPTOR(results)
        print("Owner:", sd.OwnerSid.summary())
        print("Group:", sd.GroupSid.summary())
        if getattr(sd, "DACL", None):
            print("DACL:")
            for ace in sd.DACL.Aces:
                print(" - ", ace.toSDDL())
        return sd

    @CLIUtil.addcommand()
    def query_info(self, folder: Optional[str] = None) -> None:
        """
        Query information on the current subkey
        """
        handle = self._get_cached_elt(folder)
        if handle is None:
            logger.error("Could not get handle on the specified subkey.")
            return None

        req = BaseRegQueryInfoKey_Request(
            hKey=handle,
            lpClassIn=RPC_UNICODE_STRING(),  # pointer to class name
            ndr64=True,
        )

        resp = self.client.sr1_req(req)
        if not is_status_ok(resp.status):
            logger.error("Got status %s while querying info", hex(resp.status))
            return None

        print(
            f"""
Info on key: {self.current_subkey_path}
  - Number of subkeys: {resp.lpcSubKeys}
  - Length of the longuest subkey name (in bytes): {resp.lpcbMaxSubKeyLen}
  - Number of values: {resp.lpcValues}
  - Length of the longest value name (in bytes): {resp.lpcbMaxValueNameLen}
  - Last write time: {from_filetime_to_datetime(resp.lpftLastWriteTime)}
"""
        )

    @CLIUtil.addcommand()
    def version(self):
        """
        Get remote registry server version
        """
        version = self.client.sr1_req(
            BaseRegGetVersion_Request(hKey=self.current_root_handle)
        ).lpdwVersion
        print(f"Remote registry server version: {version}")

    # --------------------------------------------- #
    #                   Backup and Restore
    # --------------------------------------------- #

    @CLIUtil.addcommand()
    def save(
        self, folder: Optional[str] = None, output_path: Optional[str] = None
    ) -> None:
        """
        Backup the current subkey to a file.
        If no folder is specified, it uses the current subkey path.
        """
        self.activate_backup()
        handle = self._get_cached_elt(folder=folder)
        key_to_save = (
            folder.split("\\")[-1] if folder else self.current_subkey_path.name
        )

        if handle is None:
            logger.error("Could not get handle on the specified subkey.")
            return None

        # Default path is %WINDIR%\System32
        if output_path is None:
            output_path = str(key_to_save) + ".reg"

        elif output_path.endswith(".reg"):
            # If the output path ends with .reg, we use it as is
            output_path = output_path.strip()

        else:
            # Otherwise, we use the current subkey path as the output path
            output_path = str(self._join_path(output_path, str(key_to_save) + ".reg"))

        print(f"Backing up {key_to_save} to {output_path}")

        sa = PRPC_SECURITY_ATTRIBUTES(
            RpcSecurityDescriptor=RPC_SECURITY_DESCRIPTOR(
                lpSecurityDescriptor=DEFAULT_SECURITY_DESCRIPTOR,
            ),
            ndr64=True,
        )
        req = BaseRegSaveKey_Request(
            hKey=handle,
            lpFile=RPC_UNICODE_STRING(Buffer=output_path),
            pSecurityAttributes=sa,
            ndr64=True,
        )

        # If the security attributes are not provided, the default security descriptor is used.
        # Meanning the file will inherite the access rights of the its parent directory.
        req.show2()
        resp = self.client.sr1_req(req)
        resp.show()
        if not is_status_ok(resp.status):
            logger.error("Got status %s while backing up", hex(resp.status))
            return None

        print(
            f"Backup of {self.current_subkey_path} saved to {self.current_subkey_path}.reg"
        )

    # --------------------------------------------- #
    #                   Operation options
    # --------------------------------------------- #

    @CLIUtil.addcommand()
    def activate_backup(self) -> None:
        """
        Activate the backup option for the registry operations (enable your backup privilege).
        This enable the backup privilege for the current session.
        """
        # check if backup privilege is already enabled
        if self.extra_options & RegOptions.REG_OPTION_BACKUP_RESTORE:
            print("Backup option is already activated. Didn't do anything.")
            return
        self.extra_options |= RegOptions.REG_OPTION_BACKUP_RESTORE
        print("Backup option activated.")
        # Clear the local cache, as the backup option will change the behavior of the registry
        self._clear_all_caches()

    @CLIUtil.addcommand()
    def disable_backup(self) -> None:
        """
        Disable the backup option for the registry operations (disable your backup privilege).
        This disable the backup privilege for the current session.
        """
        # check if backup privilege is already disabled
        if not self.extra_options & RegOptions.REG_OPTION_BACKUP_RESTORE:
            print("Backup option is already disabled. Didn't do anything.")
            return
        self.extra_options &= ~RegOptions.REG_OPTION_BACKUP_RESTORE
        print("Backup option deactivated.")
        self._clear_all_caches()

    def switch_volatile(self) -> None:
        """
        Set the registry operations to be volatile.
        This means that the registry key will be deleted when the system is restarted.
        """
        self.extra_options |= RegOptions.REG_OPTION_VOLATILE
        self.extra_options &= ~RegOptions.REG_OPTION_NON_VOLATILE
        print("Volatile option activated.")

        self._clear_all_caches()

    def disable_volatile(self) -> None:
        """
        Disable the volatile option for the registry operations.
        This means that the registry key will not be deleted when the system is restarted.
        """
        self.extra_options &= ~RegOptions.REG_OPTION_VOLATILE
        self.extra_options |= RegOptions.REG_OPTION_NON_VOLATILE
        print("Volatile option deactivated.")
        self._clear_all_caches()

    # --------------------------------------------- #
    #                   Utils
    # --------------------------------------------- #

    def get_handle_on_subkey(
        self,
        subkey_path: PureWindowsPath,
        desired_access_rights: Optional[IntFlag] = None,
    ) -> Optional[NDRContextHandle]:
        """
        Ask the remote server to return an handle on a given subkey
        """
        # If we don't have a root handle, we cannot get a subkey handle
        # This is a safety check, as we should not be able to call this function
        # without having a root handle already set.
        if self._require_root_handles(silent=True):
            return None
        if str(subkey_path) == ".":
            subkey_path = "\x00"
        else:
            subkey_path = str(subkey_path) + "\x00"

        # If no access rights were specified, we use the default read access rights
        if desired_access_rights is None:
            # Default to read access rights
            desired_access_rights = (
                AccessRights.KEY_QUERY_VALUE
                | AccessRights.KEY_ENUMERATE_SUB_KEYS
                | AccessRights.STANDARD_RIGHTS_READ
            )

        logger.debug(
            "Getting handle on subkey: %s with access rights: %s",
            subkey_path,
            desired_access_rights,
        )
        req = BaseRegOpenKey_Request(
            hKey=self.current_root_handle,
            lpSubKey=RPC_UNICODE_STRING(Buffer=subkey_path),
            samDesired=desired_access_rights,
            dwOptions=self.extra_options,
            ndr64=True,
        )

        resp = self.client.sr1_req(req)
        if not is_status_ok(resp.status):
            logger.error(
                "[-] Error : got status %s while enumerating keys", hex(resp.status)
            )
            return None

        return resp.phkResult

    def _get_cached_elt(
        self,
        folder: Optional[str] = None,
        cache_name: str = None,
        desired_access: Optional[IntFlag] = None,
    ) -> Optional[NDRContextHandle | CacheElt]:
        """
        Get the handle on the current subkey or the specified folder.
        If no folder is specified, it uses the current subkey path.
        """
        if self._require_root_handles(silent=True):
            return None

        if desired_access is None:
            # Default to read access rights
            desired_access = READ_ACCESS_RIGHTS

        # If no specific folder was specified
        # we use our current subkey path
        if folder is None or folder == "" or folder == ".":
            subkey_path = self.current_subkey_path
        # Otherwise we use the folder path,
        # the calling parent shall make sure that this path was properly sanitized
        else:
            subkey_path = self._join_path(self.current_subkey_path, folder)

        if (
            self.cache.get(cache_name, None) is not None
            and self.cache[cache_name].get(subkey_path, None) is not None
            and self.cache[cache_name][subkey_path].access == desired_access
        ):
            # If we have a cache, we check if the handle is already cached
            # If the access rights are the same, we return the cached elt
            return self.cache[cache_name][subkey_path]

        handle = self.get_handle_on_subkey(subkey_path, desired_access)
        if handle is None:
            logger.error("Could not get handle on %s", subkey_path)
            return None

        cache_elt = CacheElt(handle, desired_access, [])
        if cache_name is not None:
            self.cache[cache_name][subkey_path] = cache_elt

        return cache_elt if cache_name is not None else handle

    def _join_path(self, first_path: str, second_path: str) -> PureWindowsPath:
        return PureWindowsPath(
            os.path.normpath(
                os.path.join(
                    PureWindowsPath(first_path).as_posix(),
                    PureWindowsPath(second_path).as_posix(),
                )
            )
        )

    def _require_root_handles(self, silent: bool = False) -> bool:
        if self.current_root_handle is None:
            if not silent:
                print("No root key selected ! Use 'use' to use one.")
            return True
        return False

    def _clear_all_caches(self) -> None:
        """
        Clear all caches
        """
        for key in self.cache.keys():
            self.cache[key].clear()

    @CLIUtil.addcommand()
    def dev(self) -> NoReturn:
        """
        Joker function to jump into the python code for dev purpose
        """
        logger.info("Jumping into the code for dev purpose...")
        # pylint: disable=forgotten-debug-statement, pointless-statement
        breakpoint()


def main():
    """
    Main entry point
    """
    from scapy.utils import AutoArgparse

    AutoArgparse(RegClient)


if __name__ == "__main__":
    from scapy.utils import AutoArgparse

    AutoArgparse(RegClient)
