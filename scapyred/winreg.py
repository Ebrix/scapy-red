"""
DCE/RPC client
"""

import socket
import os
import logging

from enum import IntEnum, IntFlag, StrEnum

from ctypes.wintypes import PFILETIME
from typing import Optional, NoReturn
from pathlib import PureWindowsPath

# pylint: disable-next=import-error, no-name-in-module
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
    PRPC_SECURITY_DESCRIPTOR,
    NDRContextHandle,
    RPC_UNICODE_STRING,
)
from scapy.layers.dcerpc import (
    RPC_C_AUTHN_LEVEL,
    NDRConformantArray,
    NDRPointer,
    NDRVaryingArray,
)
from scapy.utils import (
    CLIUtil,
    valid_ip,
    valid_ip6,
)
from scapy.layers.kerberos import (
    KerberosSSP,
    krb_as_and_tgs,
    _parse_upn,
)
from scapy.config import conf
from scapy.themes import DefaultTheme
from scapy.base_classes import Net
from scapy.utils6 import Net6
from scapy.layers.msrpce.rpcclient import DCERPC_Client
from scapy.layers.dcerpc import find_dcerpc_interface, DCERPC_Transport
from scapy.layers.ntlm import MD4le, NTLMSSP
from scapy.layers.spnego import SPNEGOSSP
from scapy.layers.smb2 import SECURITY_DESCRIPTOR


conf.color_theme = DefaultTheme()
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
            breakpoint()
            return False
        return True
    except ValueError as exc:
        print(f"[!] Error: {hex(status)} - Unknown error code")
        breakpoint()
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

        if (
            self.reg_type == RegType.REG_MULTI_SZ
            or self.reg_type == RegType.REG_SZ
            or self.reg_type == RegType.REG_EXPAND_SZ
        ):
            if self.reg_type == RegType.REG_MULTI_SZ:
                # decode multiple null terminated strings
                self.reg_data = reg_data.decode("utf-16le")[:-2].replace("\x00", "\n")
            else:
                self.reg_data = reg_data.decode("utf-16le")

        elif self.reg_type == RegType.REG_BINARY:
            self.reg_data = reg_data

        elif self.reg_type == RegType.REG_DWORD or self.reg_type == RegType.REG_QWORD:
            self.reg_data = int.from_bytes(reg_data, byteorder="little")

        elif self.reg_type == RegType.REG_DWORD_BIG_ENDIAN:
            self.reg_data = int.from_bytes(reg_data, byteorder="big")

        elif self.reg_type == RegType.REG_LINK:
            self.reg_data = reg_data.decode("utf-16le")

        else:
            self.reg_data = reg_data

    def __str__(self) -> str:
        return f"{self.reg_value} ({self.reg_type.name}) {self.reg_data}"

    def __repr__(self) -> str:
        return f"RegEntry({self.reg_value}, {self.reg_type}, {self.reg_data})"


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
            ndr64=False,
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
        self.client.connect(target)
        self.client.open_smbpipe("winreg")
        self.client.bind(self.interface)
        self.ls_cache: dict[str:list] = dict()
        self.cat_cache: dict[str:list] = dict()
        self.root_handle = {}
        self.current_root_handle = None
        self.current_subkey_handle = None
        self.current_subkey_path: PureWindowsPath = PureWindowsPath("")
        if rootKey in AVAILABLE_ROOT_KEYS:
            self.current_root_path = rootKey.strip()
            self.use(self.current_root_path)
        else:
            self.current_root_path = "CHOOSE ROOT KEY"
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
            - Clears the local subkey cache (`self.ls_cache`).
            - Changes the current directory to the root of the selected registry hive.
        """

        default_read_access_rights = (
            AccessRights.KEY_QUERY_VALUE
            | AccessRights.KEY_ENUMERATE_SUB_KEYS
            | AccessRights.STANDARD_RIGHTS_READ
        )
        root_path = RootKeys(root_path)

        match root_path:
            case RootKeys.HKEY_CLASSES_ROOT:
                # Change to HKCR root
                self.current_root_handle = self.root_handle.setdefault(
                    RootKeys.HKEY_CLASSES_ROOT.value,
                    self.client.sr1_req(
                        OpenClassesRoot_Request(
                            ServerName=None, samDesired=default_read_access_rights
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
                        ),
                        timeout=self.timeout,
                    ).phKey,
                )

            case _:
                # If the root key is not recognized, raise an error
                print(f"Unknown root key: {root_path}")
                self.ls_cache.clear()
                self.current_root_handle = None
                self.current_root_path = "CHOOSE ROOT KEY"
                self.cd("")
                return

        self.current_root_path = root_path.value
        self.ls_cache.clear()
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
        # If no specific folder was specified
        # we use our current subkey path
        if folder is None or folder == "":
            cache = self.ls_cache.get(self.current_subkey_path)
            subkey_path = self.current_subkey_path

            # if the resolution was already performed,
            # no need to query again the RPC
            if cache:
                return cache

            # The first time we do an ls we need to get
            # a proper handle
            if self.current_subkey_handle is None:
                self.current_subkey_handle = self.get_handle_on_subkey(
                    PureWindowsPath("")
                )

            handle = self.current_subkey_handle

        # Otherwise we use the folder path,
        # the calling parent shall make sure that this path was properly sanitized
        else:
            subkey_path = self._join_path(self.current_subkey_path, folder)
            handle = self.get_handle_on_subkey(subkey_path)
            if handle is None:
                return []

        self.ls_cache[subkey_path] = list()
        idx = 0
        while True:
            req = BaseRegEnumKey_Request(
                hKey=handle,
                dwIndex=idx,
                lpNameIn=RPC_UNICODE_STRING(MaximumLength=1024),
                lpClassIn=RPC_UNICODE_STRING(),
                lpftLastWriteTime=None,
            )

            resp = self.client.sr1_req(req)
            if resp.status == ErrorCodes.ERROR_NO_MORE_ITEMS:
                break
            elif not is_status_ok(resp.status):
                print(
                    f"[-] Error : got status {hex(resp.status)} while enumerating keys"
                )
                self.ls_cache.clear()
                return []

            self.ls_cache[subkey_path].append(
                resp.lpNameOut.valueof("Buffer").decode("utf-8").strip("\x00")
            )
            idx += 1

        return self.ls_cache[subkey_path]

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
        # If no specific folder was specified
        # we use our current subkey path
        if folder is None or folder == "":
            cache = self.cat_cache.get(self.current_subkey_path)
            subkey_path = self.current_subkey_path

            # if the resolution was already performed,
            # no need to query again the RPC
            if cache:
                return cache

            # The first time we do a cat we need to get
            # a proper handle
            if self.current_subkey_handle is None:
                self.current_subkey_handle = self.get_handle_on_subkey(
                    PureWindowsPath("")
                )

            handle = self.current_subkey_handle

        # Otherwise we use the folder path,
        # the calling parent shall make sure that this path was properly sanitized
        else:
            subkey_path = self._join_path(self.current_subkey_path, folder)
            handle = self.get_handle_on_subkey(subkey_path)
            if handle is None:
                return []

        idx = 0
        results = []
        while True:
            req = BaseRegEnumValue_Request(
                hKey=handle,
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
            )

            resp = self.client.sr1_req(req)
            if resp.status == ErrorCodes.ERROR_NO_MORE_ITEMS:
                break
            elif not is_status_ok(resp.status):
                print(
                    f"[-] Error : got status {hex(resp.status)} while enumerating values"
                )
                self.cat_cache.clear()
                return []

            req = BaseRegQueryValue_Request(
                hKey=handle,
                lpValueName=resp.valueof("lpValueNameOut"),
                lpType=0,
                lpcbData=1024,
                lpcbLen=0,
                lpData=NDRPointer(
                    value=NDRConformantArray(
                        max_count=1024, value=NDRVaryingArray(actual_count=0, value=b"")
                    )
                ),
            )

            resp2 = self.client.sr1_req(req)
            if resp2.status == ErrorCodes.ERROR_MORE_DATA:
                # The buffer was too small, we need to retry with a larger one
                req.lpcbData = resp2.lpcbData
                req.lpData.value.max_count = resp2.lpcbData.value
<<<<<<< HEAD
                return results
                resp2 = self.client.sr1_req(req, timeout=1)
=======
<<<<<<< HEAD
                resp2 = self.client.sr1_req(req)
=======
                return results
>>>>>>> 886efa0 (Clean up and some reorganisation)
>>>>>>> 1e91a3c (Clean up and some reorganisation)

            if resp2.status:
                print(
                    f"[-] Error : got status {hex(resp2.status)} while querying value"
                )
                return []

            value = (
                resp.valueof("lpValueNameOut").valueof("Buffer").decode("utf-8").strip()
            )
            results.append(
                RegEntry(
                    reg_value=value,
                    reg_type=resp2.valueof("lpType"),
                    reg_data=resp2.valueof("lpData"),
                )
            )

            # self.cat_cache[subkey_path].append(
            #     resp.valueof("lpValueNameOut").valueof("Buffer").decode("utf-8").strip()
            # )
            idx += 1

        return results

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
        else:
            tmp_path = self._join_path(self.current_subkey_path, subkey)

        tmp_handle = self.get_handle_on_subkey(tmp_path)

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
        if self._require_root_handles(silent=True):
            return

        # If no specific folder was specified
        # we use our current subkey path
        if folder is None or folder == "":
            subkey_path = self.current_subkey_path
            handle = self.current_subkey_handle

        # Otherwise we use the folder path,
        # the calling parent shall make sure that this path was properly sanitized
        else:
            subkey_path = self._join_path(self.current_subkey_path, folder)
            handle = self.get_handle_on_subkey(subkey_path)
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
        handle = self._get_handle(folder)
        if handle is None:
            logger.error("Could not get handle on the specified subkey.")
            return None

        req = BaseRegQueryInfoKey_Request(
            hKey=handle,
            lpClassIn=RPC_UNICODE_STRING(),  # pointer to class name
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
        )

        resp = self.client.sr1_req(req)
        if not is_status_ok(resp.status):
            logger.error(
                "[-] Error : got status %s while enumerating keys", hex(resp.status)
            )
            return None

        return resp.phkResult

    def _get_handle(
        self, folder: Optional[str] = None, desired_access: Optional[IntFlag] = None
    ) -> NDRContextHandle:
        """
        Get the handle on the current subkey or the specified folder.
        If no folder is specified, it uses the current subkey path.
        """
        if self._require_root_handles(silent=True):
            return None

        # If no specific folder was specified
        # we use our current subkey path
        if folder is None or folder == "" or folder == ".":
            subkey_path = self.current_subkey_path
            handle = self.current_subkey_handle

        # Otherwise we use the folder path,
        # the calling parent shall make sure that this path was properly sanitized
        else:
            subkey_path = self._join_path(self.current_subkey_path, folder)
            handle = self.get_handle_on_subkey(subkey_path, desired_access)
            if handle is None:
                logger.error("Could not get handle on %s", subkey_path)
                return None

        return handle

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
