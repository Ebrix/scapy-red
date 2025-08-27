"""
Wrapper for the Windows Registry (winreg) using DCERPC
This module provides a client for interacting with the Windows Registry over DCERPC.
It allows for operations such as opening keys, enumerating subkeys and values, querying values,
setting values, and deleting keys or values.

The client supports authentication via NTLM or Kerberos, and can operate in a CLI mode.
It also provides utility functions for handling registry data types and error codes.
It is designed to be used with Scapy's DCERPC framework.
"""

import os
import logging
import sys

from dataclasses import dataclass
from enum import IntEnum, IntFlag, StrEnum, Enum
from ctypes.wintypes import PFILETIME
from typing import NoReturn
from pathlib import PureWindowsPath
from time import sleep

from scapy.themes import DefaultTheme
from scapy.utils import (
    CLIUtil,
)

from scapy.layers.msrpce.rpcclient import DCERPC_Client
from scapy.layers.dcerpc import (
    find_dcerpc_interface,
    DCERPC_Transport,
)
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
from scapy.error import Scapy_Exception

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
    BaseRegQueryInfoKey_Response,
    BaseRegGetKeySecurity_Request,
    BaseRegSaveKey_Request,
    BaseRegSetValue_Request,
    BaseRegCreateKey_Request,
    BaseRegDeleteKey_Request,
    BaseRegDeleteValue_Request,
    PRPC_SECURITY_DESCRIPTOR,
    PRPC_SECURITY_ATTRIBUTES,
    RPC_SECURITY_DESCRIPTOR,
    RPC_UNICODE_STRING,
    NDRContextHandle,
    NDRIntField,
)


# pylint: disable=logging-fstring-interpolation
# Set log level to benefit from Scapy warnings
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

# Create a stream handler
stream_handler = logging.StreamHandler(sys.stdout)
stream_handler.setLevel(logging.INFO)

# Create a formatter and attach it
formatter_sh = logging.Formatter("[%(levelname)s] %(message)s")
stream_handler.setFormatter(formatter_sh)

# Add the stream handler
logger.addHandler(stream_handler)

# Create a file handler
file_handler = logging.FileHandler("winreg.log")
file_handler.setLevel(logging.DEBUG)

# Create a formatter and attach it
formatter_fh = logging.Formatter("[%(levelname)s][%(funcName)s] %(message)s")
file_handler.setFormatter(formatter_fh)

# Add the file handler
logger.addHandler(file_handler)


logger.debug("Starting scapy-windows-registry module")


class GenericAccessRights(IntFlag):
    """
    Generic access rights:
    https://learn.microsoft.com/en-us/windows/win32/secauthz/generic-access-rights
    """

    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    GENERIC_EXECUTE = 0x20000000
    GENERIC_ALL = 0x10000000
    MAXIMUM_ALLOWED = 0x02000000
    ACCESS_SACL = 0x01000000


class StandardAccessRights(IntFlag):
    """
    Standard access rights:
    https://learn.microsoft.com/en-us/windows/win32/secauthz/standard-access-rights
    """

    DELETE = 0x00010000
    READ_CONTROL = 0x00020000
    WRITE_DAC = 0x00040000
    WRITE_OWNER = 0x00080000
    SYNCHRONIZE = 0x00100000

    STANDARD_RIGHTS_REQUIRED = DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER
    STANDARD_RIGHTS_ALL = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE

    STANDARD_RIGHTS_READ = READ_CONTROL
    STANDARD_RIGHTS_WRITE = READ_CONTROL
    STANDARD_RIGHTS_EXECUTE = READ_CONTROL
    SPECIFIC_RIGHTS_ALL = 0x0000FFFF


class SpecificAccessRights(IntFlag):
    """
    Access rights for registry keys:
    https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights
    """

    KEY_QUERY_VALUE = 0x00000001
    KEY_SET_VALUE = 0x00000002
    KEY_CREATE_SUB_KEY = 0x00000004
    KEY_ENUMERATE_SUB_KEYS = 0x00000008
    KEY_NOTIFY = 0x00000010
    KEY_CREATE_LINK = 0x00000020
    KEY_WOW64_64KEY = 0x0100
    KEY_WOW64_32KEY = 0x0200
    KEY_READ = (
        StandardAccessRights.STANDARD_RIGHTS_READ
        | KEY_QUERY_VALUE
        | KEY_ENUMERATE_SUB_KEYS
        | KEY_NOTIFY
    )
    KEY_EXECUTE = KEY_READ


class AccessRights(IntFlag):
    """
    Combines generic, standard, and specific access rights for registry keys.
    """

    # Generic
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SACL = GenericAccessRights.ACCESS_SACL

    # Standard
    DELETE = StandardAccessRights.DELETE
    READ_CONTROL = StandardAccessRights.READ_CONTROL
    WRITE_DAC = StandardAccessRights.WRITE_DAC
    WRITE_OWNER = StandardAccessRights.WRITE_OWNER
    SYNCHRONIZE = StandardAccessRights.SYNCHRONIZE
    STANDARD_RIGHTS_REQUIRED = (
        StandardAccessRights.DELETE
        | StandardAccessRights.READ_CONTROL
        | StandardAccessRights.WRITE_DAC
        | StandardAccessRights.WRITE_OWNER
    )
    STANDARD_RIGHTS_READ = StandardAccessRights.READ_CONTROL
    STANDARD_RIGHTS_WRITE = StandardAccessRights.READ_CONTROL
    STANDARD_RIGHTS_EXECUTE = StandardAccessRights.READ_CONTROL
    STANDARD_RIGHTS_ALL = (
        StandardAccessRights.DELETE
        | StandardAccessRights.READ_CONTROL
        | StandardAccessRights.WRITE_DAC
        | StandardAccessRights.WRITE_OWNER
        | StandardAccessRights.SYNCHRONIZE
    )
    SPECIFIC_RIGHTS_ALL = StandardAccessRights.SPECIFIC_RIGHTS_ALL

    # Specific
    KEY_QUERY_VALUE = SpecificAccessRights.KEY_QUERY_VALUE
    KEY_SET_VALUE = SpecificAccessRights.KEY_SET_VALUE
    KEY_CREATE_SUB_KEY = SpecificAccessRights.KEY_CREATE_SUB_KEY
    KEY_ENUMERATE_SUB_KEYS = SpecificAccessRights.KEY_ENUMERATE_SUB_KEYS
    KEY_NOTIFY = SpecificAccessRights.KEY_NOTIFY
    KEY_CREATE_LINK = SpecificAccessRights.KEY_CREATE_LINK
    KEY_WOW64_64KEY = SpecificAccessRights.KEY_WOW64_64KEY
    KEY_WOW64_32KEY = SpecificAccessRights.KEY_WOW64_32KEY

    KEY_READ = (
        StandardAccessRights.READ_CONTROL
        | SpecificAccessRights.KEY_QUERY_VALUE
        | SpecificAccessRights.KEY_ENUMERATE_SUB_KEYS
        | SpecificAccessRights.KEY_NOTIFY
    )
    KEY_EXECUTE = KEY_READ
    KEY_WRITE = (
        STANDARD_RIGHTS_ALL
        | SpecificAccessRights.KEY_SET_VALUE
        | SpecificAccessRights.KEY_CREATE_SUB_KEY
    )
    KEY_ALL_ACCESS = (
        STANDARD_RIGHTS_REQUIRED
        | SpecificAccessRights.KEY_QUERY_VALUE
        | SpecificAccessRights.KEY_SET_VALUE
        | SpecificAccessRights.KEY_CREATE_SUB_KEY
        | SpecificAccessRights.KEY_ENUMERATE_SUB_KEYS
        | SpecificAccessRights.KEY_NOTIFY
        | SpecificAccessRights.KEY_CREATE_LINK
    )


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
    ERROR_FILE_NOT_FOUND = 0x00000002
    ERROR_PATH_NOT_FOUND = 0x00000003
    ERROR_ACCESS_DENIED = 0x00000005
    ERROR_INVALID_HANDLE = 0x00000006
    ERROR_NOT_SAME_DEVICE = 0x00000011
    ERROR_WRITE_PROTECT = 0x00000013
    ERROR_INVALID_PARAMETER = 0x00000057
    ERROR_CALL_NOT_IMPLEMENTED = 0x00000057
    ERROR_INVALID_NAME = 0x0000007B
    ERROR_BAD_PATHNAME = 0x000000A1
    ERROR_ALREADY_EXISTS = 0x000000B7
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
    HKEY_CLASSES_ROOT = "HKCR"

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
    HKEY_CURRENT_CONFIG = "HKCC"

    # This key define the default user configuration for new users on the local computer and the
    # user configuration for the current user.
    HKEY_USERS = "HKU"

    # Registry entries subordinate to this key allow access to performance data.
    HKEY_PERFORMANCE_DATA = "HKPD"

    # Registry entries subordinate to this key reference the text strings that describe counters
    # in U.S. English.
    HKEY_PERFORMANCE_TEXT = "HKPT"

    # Registry entries subordinate to this key reference the text strings that describe
    # counters in the local language of the area in which the computer is running.
    HKEY_PERFORMANCE_NLSTEXT = "HKPN"

    def __new__(cls, value):
        # 1. Strip and uppercase the raw input
        normalized = value.strip().upper()
        # 2. Create the enum member with the normalized value
        obj = str.__new__(cls, normalized)
        obj._value_ = normalized
        return obj

    @classmethod
    def from_value(cls, value: str):
        """Convert a string to a RootKeys enum member."""
        value = value.strip().upper()
        match value:
            case "HKEY_CLASSES_ROOT":
                value = RootKeys.HKEY_CLASSES_ROOT.value
            case "HKEY_CURRENT_USER":
                value = RootKeys.HKEY_CURRENT_USER.value
            case "HKEY_LOCAL_MACHINE":
                value = RootKeys.HKEY_LOCAL_MACHINE.value
            case "HKEY_CURRENT_CONFIG":
                value = RootKeys.HKEY_CURRENT_CONFIG.value
            case "HKEY_USERS":
                value = RootKeys.HKEY_USERS.value
            case "HKEY_PERFORMANCE_DATA":
                value = RootKeys.HKEY_PERFORMANCE_DATA.value
            case "HKEY_PERFORMANCE_TEXT":
                value = RootKeys.HKEY_PERFORMANCE_TEXT.value
            case "HKEY_PERFORMANCE_NLSTEXT":
                value = RootKeys.HKEY_PERFORMANCE_NLSTEXT.value

        try:
            return cls(value)
        except ValueError:
            print(f"Unknown root key: {value}.")


class RegType(IntEnum):
    """
    Registry value types
    """

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
        logger.info(f"Unknown registry type: {value}, using UNK")
        unk = cls.UNK
        unk.real_value = value
        return unk

    def __new__(cls, value, real_value=None):
        obj = int.__new__(cls, value)
        obj._value_ = value
        if real_value is None:
            real_value = value
        obj.real_value = real_value
        return obj

    @classmethod
    def fromvalue(cls, value: str | int) -> "RegType":
        """Convert a string to a RegType enum member.
        :param value: The string representation of the registry type.
        :return: The corresponding RegType enum member.
        """

        if isinstance(value, int):
            try:
                return cls(value)
            except ValueError:
                logger.info(f"Unknown registry type: {value}, using UNK")
                return cls.UNK

        value = value.strip().upper()
        try:
            return cls(int(value))
        except (ValueError, KeyError):
            logger.info(f"Unknown registry type: {value}, using UNK")
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
            logger.error("Error: %s - %s", hex(err.value), ErrorCodes(status).name)
            return False
        return True
    except ValueError as exc:
        logger.error("Error: %s - Unknown error code", hex(status))
        raise ValueError(f"Error: {hex(status)} - Unknown error code") from exc


# Global constant used to easily record
# the root keys available and prevent typos
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


class WellKnownSIDs(Enum):
    """
    Well-known SIDs.

    .. notes::
    This class should be filled with more values as needs arise
    """

    SY = WINNT_SID.fromstr("S-1-5-18")  # Local System
    BA = WINNT_SID.fromstr("S-1-5-32-544")  # Built-in Administrators


DEFAULT_SECURITY_DESCRIPTOR = SECURITY_DESCRIPTOR(
    Control=0x1000 | 0x8000 | 0x4,
    # OwnerSid=WellKnownSIDs.SY.value,  # Local System SID
    # GroupSid=WellKnownSIDs.SY.value,  # Local System SID
    DACL=WINNT_ACL(
        AclRevision=2,
        Sbz1=0,
        AclSize=0xFF,
        Aces=[
            WINNT_ACE_HEADER(
                AceType=0x0,  # ACCESS_ALLOWED_ACE_TYPE
                AceFlags=0x0,  # No flags
            )
            / WINNT_ACCESS_ALLOWED_ACE(
                Mask=AccessRights.GENERIC_ALL,  # GA
                Sid=WellKnownSIDs.BA.value,  # Built-in Administrators SID
            ),
        ],
    ),
    ndr64=True,
)

# For now we force the AclSize to the length of the Acl
DEFAULT_SECURITY_DESCRIPTOR.Data[0][1][WINNT_ACL].AclSize = len(
    DEFAULT_SECURITY_DESCRIPTOR.Data[0][1][WINNT_ACL]
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
                    self.reg_data = reg_data.decode("utf-16le")[:-1].replace(
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

    @staticmethod
    def encode_data(reg_type: RegType, data: str) -> bytes:
        """
        Encode data based on the type.
        """

        match reg_type:
            case RegType.REG_MULTI_SZ | RegType.REG_SZ | RegType.REG_EXPAND_SZ:
                if reg_type == RegType.REG_MULTI_SZ:
                    # decode multiple null terminated strings
                    return data.replace("\\n", "\x00").encode("utf-16le") + b"\x00\x00"
                else:
                    return data.encode("utf-16le")

            case RegType.REG_BINARY:
                return data.encode("utf-8").decode("unicode_escape").encode("latin1")

            case RegType.REG_DWORD | RegType.REG_QWORD:
                bit_length = (int(data).bit_length() + 7) // 8
                return int(data).to_bytes(bit_length, byteorder="little")

            case RegType.REG_DWORD_BIG_ENDIAN:
                bit_length = (int(data).bit_length() + 7) // 8
                return int(data).to_bytes(bit_length, byteorder="big")

            case RegType.REG_LINK:
                return data.encode("utf-16le")

            case _:
                return data.encode("utf-8").decode("unicode_escape").encode("latin1")

    def __str__(self) -> str:
        if self.reg_type == RegType.UNK:
            return f"{self.reg_value} ({self.reg_type.name}:{self.reg_type.real_value}) {self.reg_data}"
        return f"{self.reg_value} ({self.reg_type.name}:{self.reg_type.value}) {self.reg_data}"

    def __repr__(self) -> str:
        return f"RegEntry({self.reg_value}, {self.reg_type}, {self.reg_data})"


@dataclass
class CacheElt:
    """
    Cache element to store the handle and the subkey path
    """

    # Handle on a remote object
    handle: NDRContextHandle

    # Requested AccessRights for this handle
    access: AccessRights

    # List of elements returned by the server
    # using this handle. For example a list of subkeys or values.
    values: list


@conf.commands.register
class RegClient(CLIUtil):
    r"""
    A simple registry CLI

    :param target: can be a hostname, the IPv4 or the IPv6 to connect to
    :param UPN: the upn to use (DOMAIN/USER, DOMAIN\USER, USER@DOMAIN or USER)
    :param password: (string) if provided, used for auth
    :param guest: use guest mode (over NTLM)
    :param ssp: if provided, use this SSP for auth.
    :param kerberos: if available, whether to use Kerberos or not
    :param kerberos_required: require kerberos
    :param port: the TCP port. default 445
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
        HashAes128Sha96: str = None,
        HashAes256Sha96: str = None,
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
        assert UPN or ssp or guest, "Either UPN, ssp or guest must be provided !"
        # Do we need to build a SSP?
        if ssp is None:
            # Create the SSP (only if not guest mode)
            if not guest:
                ssp = SPNEGOSSP.from_cli_arguments(
                    UPN=UPN,
                    target=target,
                    password=password,
                    HashNt=HashNt,
                    HashAes256Sha96=HashAes256Sha96,
                    HashAes128Sha96=HashAes128Sha96,
                    ST=ST,
                    KEY=KEY,
                    kerberos_required=kerberos_required,
                )
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
            self.client.connect(target, timeout=self.timeout)

            sleep(1.5)
            self.client.open_smbpipe("winreg")
            self.client.bind(self.interface)

        except ValueError as exc:
            logger.warning(
                f"Remote service didn't seem to be running. Let's try again now that we should have trigger it. ({exc})"
            )

            sleep(1.5)
            self.client.open_smbpipe("winreg")
            self.client.bind(self.interface)
        except Scapy_Exception as e:
            if str(3221225566) in str(e):
                logger.error(
                    f"""
    [!] STATUS_LOGON_FAILURE - {e}  You used:
        - UPN {UPN},
        - password {password},
        - target {target},
        - guest {guest},
        - kerberos {kerberos},
        - kerberos_required {kerberos_required},
        - HashNt {HashNt},
        - HashAes128Sha96 {HashAes128Sha96},
        - HashAes256Sha96 {HashAes256Sha96},
        - ST {ST},
        - KEY {KEY}

    [💡 TIPS] If you want to use a local account you may use something like: UPN = "WORKGROUP\\\\Administrator" or UPN = "Administrator@WORKGROUP" or "Administrator@192.168.1.2"
"""
                )
                exit()
        except TimeoutError as exc:
            logger.error(
                f"[!] Timeout while connecting to {target}:{port}. Check service status. {exc}"
            )
            sys.exit(-1)

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
        self.exploration_mode = False
        self.current_subkey_path: PureWindowsPath = PureWindowsPath("")
        self.sam_requested_access_rights = AccessRights.MAXIMUM_ALLOWED
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
    def close(self) -> None:
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

        Behavior:
            - Determines which registry root to use based on the prefix of `root_path`.
            - Opens the corresponding registry root handle if not already opened, using the appropriate request.
            - Clears the local subkey cache
            - Changes the current directory to the root of the selected registry hive.

        :param root_path: The root registry path to use. Should start with one of the following:
            - HKCR
            - HKLM
            - HKCU
            - HKCC
            - HKU
            - HKPD
            - HKPT
            - HKPN
        """

        root_path = RootKeys(root_path.upper().strip())

        match root_path:
            case RootKeys.HKEY_CLASSES_ROOT:
                # Change to HKCR root
                logger.debug("Changing to HKCR root")
                self.current_root_handle = self.root_handle.setdefault(
                    RootKeys.HKEY_CLASSES_ROOT.value,
                    self.client.sr1_req(
                        OpenClassesRoot_Request(
                            ServerName=None,
                            samDesired=self.sam_requested_access_rights,
                            ndr64=True,
                        ),
                        timeout=self.timeout,
                    ).phKey,
                )

            case RootKeys.HKEY_CURRENT_USER:
                # Change to HKCU root
                logger.debug("Changing to HKCU root")
                self.current_root_handle = self.root_handle.setdefault(
                    RootKeys.HKEY_CURRENT_USER.value,
                    self.client.sr1_req(
                        OpenCurrentUser_Request(
                            ServerName=None,
                            samDesired=self.sam_requested_access_rights,
                            ndr64=True,
                        ),
                        timeout=self.timeout,
                    ).phKey,
                )

            case RootKeys.HKEY_LOCAL_MACHINE:
                # Change to HKLM root
                logger.debug("Changing to HKLM root")
                self.current_root_handle = self.root_handle.setdefault(
                    RootKeys.HKEY_LOCAL_MACHINE.value,
                    self.client.sr1_req(
                        OpenLocalMachine_Request(
                            ServerName=None,
                            samDesired=self.sam_requested_access_rights,
                            ndr64=True,
                        ),
                        timeout=self.timeout,
                    ).phKey,
                )

            case RootKeys.HKEY_CURRENT_CONFIG:
                # Change to HKCC root
                logger.debug("Changing to HKCC root")
                self.current_root_handle = self.root_handle.setdefault(
                    RootKeys.HKEY_CURRENT_CONFIG.value,
                    self.client.sr1_req(
                        OpenCurrentConfig_Request(
                            ServerName=None,
                            samDesired=self.sam_requested_access_rights,
                            ndr64=True,
                        ),
                        timeout=self.timeout,
                    ).phKey,
                )

            case RootKeys.HKEY_USERS:
                # Cange to HKU root
                logger.debug("Changing to HKU root")
                self.current_root_handle = self.root_handle.setdefault(
                    RootKeys.HKEY_USERS.value,
                    self.client.sr1_req(
                        OpenUsers_Request(
                            ServerName=None,
                            samDesired=self.sam_requested_access_rights,
                            ndr64=True,
                        ),
                        timeout=self.timeout,
                    ).phKey,
                )

            case RootKeys.HKEY_PERFORMANCE_DATA:
                # Change to HKPD root
                logger.debug("Changing to HKPD root")
                self.current_root_handle = self.root_handle.setdefault(
                    RootKeys.HKEY_PERFORMANCE_DATA.value,
                    self.client.sr1_req(
                        OpenPerformanceData_Request(
                            ServerName=None,
                            samDesired=0,
                            ndr64=True,
                        ),
                        timeout=self.timeout,
                    ).phKey,
                )

            case RootKeys.HKEY_PERFORMANCE_TEXT:
                # Change to HKPT root
                logger.debug("Changing to HKPT root")
                self.current_root_handle = self.root_handle.setdefault(
                    RootKeys.HKEY_PERFORMANCE_TEXT.value,
                    self.client.sr1_req(
                        OpenPerformanceText_Request(
                            ServerName=None,
                            samDesired=0,
                            ndr64=True,
                        ),
                        timeout=self.timeout,
                    ).phKey,
                )

            case RootKeys.HKEY_PERFORMANCE_NLSTEXT:
                # Change to HKPN root
                logger.debug("Changing to HKPN root")
                self.current_root_handle = self.root_handle.setdefault(
                    RootKeys.HKEY_PERFORMANCE_NLSTEXT.value,
                    self.client.sr1_req(
                        OpenPerformanceNlsText_Request(
                            ServerName=None,
                            samDesired=0,
                            ndr64=True,
                        ),
                        timeout=self.timeout,
                    ).phKey,
                )

            case _:
                # If the root key is not recognized, raise an error
                logger.error(f"Unknown root key: {root_path}")
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
    def ls(self, subkey: str | None = None) -> list[str]:
        """
        EnumKeys of the current subkey path
        """

        # Try to use the cache
        res = self._get_cached_elt(subkey=subkey, cache_name="ls")
        if res is None:
            return []
        elif len(res.values) != 0:
            # If the resolution was already performed,
            # no need to query again the RPC
            return res.values

        if subkey is None:
            subkey = ""

        subkey_path = self._join_path(self.current_subkey_path, subkey)

        idx = 0
        logger.debug("Enumerating keys in %s", subkey_path)
        while True:
            req = BaseRegEnumKey_Request(
                hKey=res.handle,
                dwIndex=idx,
                lpNameIn=RPC_UNICODE_STRING(MaximumLength=1024),
                lpClassIn=RPC_UNICODE_STRING(),
                lpftLastWriteTime=None,
                ndr64=True,
            )

            # Send request
            resp = self.client.sr1_req(req)
            if resp.status == ErrorCodes.ERROR_NO_MORE_ITEMS:
                break

            # Check the response status
            elif not is_status_ok(resp.status):
                logger.error("Got status %s while enumerating keys", hex(resp.status))
                self.cache["ls"].pop(subkey_path, None)
                return []

            self.cache["ls"][subkey_path].values.append(
                resp.lpNameOut.valueof("Buffer").decode("utf-8").strip("\x00")
            )
            idx += 1

        return self.cache["ls"][subkey_path].values

    @CLIUtil.addoutput(ls)
    def ls_output(self, results: list[str]) -> None:
        """
        Print the output of 'ls'
        """
        for subkey in results:
            print(subkey)

    @CLIUtil.addcomplete(ls)
    def ls_complete(self, subkey: str) -> list[str]:
        """
        Auto-complete ls
        """
        if self._require_root_handles(silent=True):
            return []

        subkey = subkey.strip().replace("/", "\\")
        if "\\" in subkey:
            parent = "\\".join(subkey.split("\\")[:-1])
            subkey = subkey.split("\\")[-1]
        else:
            parent = ""

        return [
            str(self._join_path(parent, str(subk)))
            for subk in self.ls(parent)
            if str(subk).lower().startswith(subkey.lower())
        ]

    @CLIUtil.addcommand(spaces=True)
    def cat(self, subkey: str | None = None) -> list[RegEntry]:
        """
        Enumerates and retrieves registry values for a given subkey path.

        If no subkey is specified, uses the current subkey path and caches results to avoid redundant RPC queries.
        Otherwise, enumerates values under the specified subkey path.

        Args:
            subkey (str | None): The subkey path to enumerate. If None or empty, uses the current subkey path.

        Returns:
            list[RegEntry]: A list of registry entries (as RegEntry objects) for the specified subkey path.
                            Returns an empty list if the handle is invalid or an error occurs during enumeration.

        Side Effects:
            - May print error messages to standard output if RPC queries fail.
            - Updates internal cache for previously enumerated subkey paths.
        """

        # Try to use the cache
        res = self._get_cached_elt(subkey=subkey, cache_name="cat")
        if res is None:
            return []
        elif len(res.values) != 0:
            # If the resolution was already performed,
            # no need to query again the RPC
            return res.values

        subkey_path = self._join_path(self.current_subkey_path, subkey)

        idx = 0
        logger.debug("Enumerating values in %s", subkey_path)
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

            # Send request
            resp = self.client.sr1_req(req)
            if resp.status == ErrorCodes.ERROR_NO_MORE_ITEMS:
                break

            # Check the response status
            elif not is_status_ok(resp.status):
                logger.error("got status %s while enumerating values", hex(resp.status))
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

            # Send request
            resp2 = self.client.sr1_req(req)
            if resp2.status == ErrorCodes.ERROR_MORE_DATA:
                # The buffer was too small, we need to retry with a larger one
                req.lpcbData = resp2.lpcbData
                req.lpData.value.max_count = resp2.lpcbData.value
                resp2 = self.client.sr1_req(req)

            # Check the response status
            if not is_status_ok(resp2.status):
                logger.error("got status %s while querying value", hex(resp2.status))
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
            if entry.reg_type == RegType.UNK:
                print(
                    f"  - {entry.reg_value:<20} {'(' + entry.reg_type.name + " - " + str(entry.reg_type.real_value) + ')':<15} {entry.reg_data}"
                )
            print(
                f"  - {entry.reg_value:<20} {'(' + entry.reg_type.name + " - " + str(entry.reg_type.value) + ')':<15} {entry.reg_data}"
            )

    @CLIUtil.addcomplete(cat)
    def cat_complete(self, subkey: str) -> list[str]:
        """
        Auto-complete cat
        """
        return self.ls_complete(subkey)

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
            # Try to use the cache
            res = self._get_cached_elt(
                subkey=subkey,
                cache_name="cd",
            )
            tmp_handle = res.handle if res else None
            tmp_path = self._join_path(self.current_subkey_path, subkey)

        if tmp_handle is not None:
            # If the handle was successfully retrieved,
            # we update the current subkey path and handle
            self.current_subkey_path = tmp_path
            self.current_subkey_handle = tmp_handle

        if self.exploration_mode:
            # force the trigger of the UTILS.OUTPUT command (cd_output)
            return f"[{self.current_root_path}:\\{self.current_subkey_path}]"

    @CLIUtil.addcomplete(cd)
    def cd_complete(self, subkey: str) -> list[str]:
        """
        Auto-complete cd
        """

        return self.ls_complete(subkey)

    @CLIUtil.addoutput(cd)
    def cd_output(self, pwd) -> None:
        """
        Print the output of 'cd'
        """

        if self.exploration_mode:
            print(pwd)
            print("-" * 10 + " SubKeys" + "-" * 10)
            self.ls_output(self.ls())
            print("-" * 10 + " Values" + "-" * 10)
            self.cat_output(self.cat())

    @CLIUtil.addcommand()
    def activate_exploration_mode(self) -> None:
        """
        Activate exploration mode: perform ls and cat automatically when changing directory
        """

        self.exploration_mode = True
        print("Exploration mode activated")

    @CLIUtil.addcommand()
    def disable_exploration_mode(self) -> None:
        """
        Disable exploration mode
        """

        self.exploration_mode = False
        print("Exploration mode disabled")

    # --------------------------------------------- #
    #                   Get Information
    # --------------------------------------------- #

    @CLIUtil.addcommand()
    def get_sd(self, subkey: str | None = None) -> SECURITY_DESCRIPTOR | None:
        """
        Get the security descriptor of the current subkey. SACL are not retrieve at this point (TODO).
        """

        # Try to use the cache
        handle = self._get_cached_elt(subkey=subkey)
        if handle is None:
            return None

        # Log and execute
        logger.debug("Getting security descriptor for %s", subkey)
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

        # Send request
        resp = self.client.sr1_req(req)
        if resp.status == ErrorCodes.ERROR_INSUFFICIENT_BUFFER:
            # The buffer was too small, we need to retry with a larger one
            req.pRpcSecurityDescriptorIn.cbInSecurityDescriptor = (
                resp.pRpcSecurityDescriptorOut.cbInSecurityDescriptor
            )
            resp = self.client.sr1_req(req)

        # Check the response status
        if not is_status_ok(resp.status):
            logger.error("Got status %s while getting security", hex(resp.status))
            return None

        sd = SECURITY_DESCRIPTOR(
            resp.pRpcSecurityDescriptorOut.valueof("lpSecurityDescriptor")
        )
        return sd

    @CLIUtil.addoutput(get_sd)
    def get_sd_output(self, sd: SECURITY_DESCRIPTOR | None) -> None:
        """
        Print the output of 'get_sd'
        """

        if sd is None:
            print("No security descriptor found.")
            return
        else:
            print("Owner:", sd.OwnerSid.summary())
            print("Group:", sd.GroupSid.summary())
            if getattr(sd, "DACL", None):
                print("DACL:")
                for ace in sd.DACL.Aces:
                    print(" - ", ace.toSDDL())

    @CLIUtil.addcommand()
    def query_info(
        self, subkey: str | None = None
    ) -> BaseRegQueryInfoKey_Response | None:
        """
        Query information on the current subkey

        :param subkey: The subkey to query. If None, it uses the current subkey path.
        :return: BaseRegQueryInfoKey_Response object containing information about the subkey.
                 Returns None if the handle is invalid or an error occurs during the query.
        """

        # Try to use the cache
        handle = self._get_cached_elt(subkey)
        if handle is None:
            logger.error("Could not get handle on the specified subkey.")
            return None

        # Log and execute
        logger.debug("Querying info for %s", subkey)
        req = BaseRegQueryInfoKey_Request(
            hKey=handle,
            lpClassIn=RPC_UNICODE_STRING(),  # pointer to class name
            ndr64=True,
        )

        # Send request
        resp = self.client.sr1_req(req)

        # Check the response status
        if not is_status_ok(resp.status):
            logger.error("Got status %s while querying info", hex(resp.status))
            return None
        return resp

    @CLIUtil.addoutput(query_info)
    def query_info_output(self, info: None) -> None:
        """
        Print the output of 'query_info'
        """

        if info is None:
            print("No information found.")
            return

        print(
            f"""
Info on key:
  - Number of subkeys: {info.lpcSubKeys}
  - Length of the longest subkey name (in bytes): {info.lpcbMaxSubKeyLen}
  - Number of values: {info.lpcValues}
  - Length of the longest value name (in bytes): {info.lpcbMaxValueNameLen}
  - Last write time: {from_filetime_to_datetime(info.lpftLastWriteTime)}
"""
        )

    @CLIUtil.addcommand()
    def version(self) -> NDRIntField:
        """
        Get remote registry server version of the current subkey
        """

        logger.debug("Getting remote registry server version")
        return self.client.sr1_req(
            BaseRegGetVersion_Request(hKey=self.current_subkey_handle, ndr64=True)
        ).lpdwVersion

    @CLIUtil.addoutput(version)
    def version_output(self, version: int) -> None:
        """
        Print the output of 'version'
        """

        print(f"Remote registry server version: {version}")

    # --------------------------------------------- #
    #                  Modify                       #
    # --------------------------------------------- #

    @CLIUtil.addcommand()
    def set_value(
        self,
        value_name: str,
        value_type: RegType | str,
        value_data: str,
        subkey: str | None = None,
    ) -> None:
        """
        Set a registry value in the current subkey.
        If no subkey is specified, it uses the current subkey path.
        """

        # Validate the value type
        try:
            value_type = RegType.fromvalue(value_type)
        except ValueError:
            logger.error("Unknown registry type: %s", value_type)
            return None

        data = RegEntry.encode_data(value_type, value_data)

        # Try to use the cache
        handle = self._get_cached_elt(
            subkey=subkey, desired_access=AccessRights.KEY_WRITE
        )
        if handle is None:
            logger.error("Could not get handle on the specified subkey.")
            return None

        if subkey is None:
            subkey_path = self.current_subkey_path
        else:
            subkey_path = self._join_path(self.current_subkey_path, subkey)

        # Log and execute
        logger.debug(
            "Setting value %s of type %s in %s",
            value_name,
            value_type.name,
            subkey_path,
        )
        req = BaseRegSetValue_Request(
            hKey=handle,
            lpValueName=RPC_UNICODE_STRING(Buffer=value_name + "\x00"),
            dwType=value_type.value,
            lpData=data,
            ndr64=True,
        )

        # Send request
        resp = self.client.sr1_req(req)

        # We remove the entry from the cache if it exists
        # Even if the response status is not OK, we want to remove it
        if subkey_path in self.cache["cat"]:
            self.cache["cat"].pop(subkey_path, None)

        # Check the response status
        if not is_status_ok(resp.status):
            logger.error("Got status %s while setting value", hex(resp.status))
            return None

    @CLIUtil.addcommand()
    def create_key(self, new_key: str, subkey: str | None = None) -> None:
        """
        Create a new key named as the specified `new_key` under the `subkey`.
        If no subkey is specified, it uses the current subkey path.

        :param new_key: name a the new key to create
        :param subkey: relative subkey to create the the new key
        """

        # Try to use the cache
        handle = self._get_cached_elt(
            subkey=subkey,
            desired_access=AccessRights.KEY_CREATE_SUB_KEY,
        )
        if handle is None:
            logger.error("Could not get handle on the specified subkey.")
            return None

        if subkey is None:
            subkey_path = self.current_subkey_path
        else:
            subkey_path = self._join_path(self.current_subkey_path, subkey)

        # Log and execute
        logger.debug("Creating key %s under %s", new_key, subkey_path)
        req = BaseRegCreateKey_Request(
            hKey=handle,
            lpSubKey=RPC_UNICODE_STRING(Buffer=new_key + "\x00"),
            samDesired=self.sam_requested_access_rights,
            dwOptions=self.extra_options,
            lpSecurityAttributes=None,
            ndr64=True,
        )

        # Send request
        resp = self.client.sr1_req(req)

        # We remove the entry from the cache if it exists
        # Even if the response status is not OK, we want to remove it
        if subkey_path.parent in self.cache["ls"]:
            self.cache["ls"].pop(subkey_path.parent, None)
        if subkey_path in self.cache["cat"]:
            self.cache["cat"].pop(subkey_path, None)

        # Check the response status
        if not is_status_ok(resp.status):
            logger.error("Got status %s while creating key", hex(resp.status))
            return None
        print(f"Key {new_key} created successfully.")

    @CLIUtil.addcommand(spaces=True)
    def delete_key(self, subkey: str | None = None) -> None:
        """
        Delete the specified subkey. If no subkey is specified, it uses the current subkey path.
        Proper same access rights are required to delete a key. By default we request MAXIMUM_ALLOWED.
        So no issue.

        :param subkey: The subkey to delete. If None, it uses the current subkey path.
        """

        # Make sure that we have a backup activated
        self.activate_backup()

        # Determine the subkey path for logging and cache purposes
        if subkey is None:
            subkey_path = self.current_subkey_path
        else:
            subkey_path = self._join_path(self.current_subkey_path, subkey)

        # Log and execute
        logger.debug("Deleting key %s", subkey_path)
        req = BaseRegDeleteKey_Request(
            hKey=self.current_root_handle,
            lpSubKey=RPC_UNICODE_STRING(Buffer=str(subkey_path) + "\x00"),
            ndr64=True,
        )

        # Send request
        resp = self.client.sr1_req(req)

        # We remove the entry from the cache if it exists
        # Even if the response status is not OK, we want to remove it
        if subkey_path.parent in self.cache["ls"]:
            self.cache["ls"].pop(subkey_path.parent, None)
        if subkey_path in self.cache["cat"]:
            self.cache["cat"].pop(subkey_path, None)

        # Check the response status
        if not is_status_ok(resp.status):
            logger.error("Got status %s while deleting key", hex(resp.status))
            return None

        print(f"Key {subkey} deleted successfully.")

    @CLIUtil.addcomplete(delete_key)
    def delete_key_complete(self, subkey: str) -> list[str]:
        """
        Auto-complete delete_key
        """

        return self.ls_complete(subkey)

    @CLIUtil.addcommand()
    def delete_value(self, value: str = "", subkey: str | None = None) -> None:
        """
        Delete the specified value.
        If no subkey is specified, it uses the current subkey path.
        If no value is specified, it will delete the default value of the subkey, but subkey cannot be specified.

        :param subkey: The subkey to delete. If None, it uses the current subkey path.
        """

        # Make sure that we have a backup activated
        self.activate_backup()

        # Try to use the cache
        handle = self._get_cached_elt(
            subkey=subkey, desired_access=AccessRights.KEY_WRITE
        )
        if handle is None:
            logger.error("Could not get handle on the specified subkey.")
            return None

        # Determine the subkey path for logging and cache purposes
        if subkey is None:
            subkey_path = self.current_subkey_path
        else:
            subkey_path = self._join_path(self.current_subkey_path, subkey)

        # Log and execute
        logger.debug("Deleting value %s in %s", value, subkey_path)
        req = BaseRegDeleteValue_Request(
            hKey=handle,
            lpValueName=RPC_UNICODE_STRING(Buffer=value + "\x00"),
            ndr64=True,
        )

        # Send request
        resp = self.client.sr1_req(req)

        # We remove the entry from the cache if it exists
        # Even if the response status is not OK, we want to remove it
        if subkey_path in self.cache["cat"]:
            self.cache["cat"].pop(subkey_path, None)

        # Check the response status
        if not is_status_ok(resp.status):
            logger.error("Got status %s while setting value", hex(resp.status))
            return None

        print(f"Value {value} deleted successfully.")

    @CLIUtil.addcomplete(delete_value)
    def delete_value_complete(self, value: str) -> list[str]:
        """
        Auto-complete delete_value
        """

        if self._require_root_handles(silent=True):
            return []

        value = value.strip()
        return [
            subval.reg_value.strip("\x00")
            for subval in self.cat()
            if str(subval.reg_value).lower().startswith(value.lower())
        ]

    # --------------------------------------------- #
    #                   Backup and Restore
    # --------------------------------------------- #

    @CLIUtil.addcommand()
    def save(
        self,
        output_path: str | None = None,
        subkey: str | None = None,
        fsecurity: bool = False,
    ) -> None:
        """
        Backup the current subkey to a file. If no subkey is specified, it uses the current subkey path. If no output_path is specified,
        it will be saved in the `%WINDIR%\\System32` directory with the name of the subkey and .reg extension.

        :param output_path: The path to save the backup file. If None, it defaults to the current subkey name with .reg extension.
                            If the output path ends with .reg, it uses it as is, otherwise it appends .reg to the output path.
        :param subkey: The subkey to backup. If None, it uses the current subkey path.
        :return: None, by default it saves the backup to a file protected so that only BA can read it.
        """

        # Make sure that we have a backup activated
        self.activate_backup()

        # Try to use the cache
        handle = self._get_cached_elt(subkey=subkey)
        key_to_save = (
            subkey.split("\\")[-1] if subkey else self.current_subkey_path.name
        )

        if handle is None:
            logger.error("Could not get handle on the specified subkey.")
            return None

        # Default path is %WINDIR%\System32
        if output_path is None:
            output_path = str(key_to_save) + ".reg"

        elif output_path.endswith(".reg"):
            # If the output path ends with .reg, we use it as is
            output_path = str(self._join_path("", output_path))

        else:
            # Otherwise, we use the current subkey path as the output path
            output_path = str(self._join_path(output_path, str(key_to_save) + ".reg"))

        if fsecurity:
            print(
                "Looks like you don't like security so much. Hope you know what you are doing."
            )
            logger.warning("Disabling security built-in protections while saving.")
            sa = None
        else:
            sa = PRPC_SECURITY_ATTRIBUTES(
                RpcSecurityDescriptor=RPC_SECURITY_DESCRIPTOR(
                    lpSecurityDescriptor=DEFAULT_SECURITY_DESCRIPTOR,
                ),
                bInheritHandle=False,
                ndr64=True,
            )
            sa.nLength = len(sa)

        # Log and execute
        logger.debug("Backing up %s to %s", key_to_save, output_path)
        req = BaseRegSaveKey_Request(
            hKey=handle,
            lpFile=RPC_UNICODE_STRING(Buffer=output_path),
            pSecurityAttributes=sa,
            ndr64=True,
        )

        # Send request
        resp = self.client.sr1_req(req)

        # Check the response status
        if not is_status_ok(resp.status):
            logger.error("Got status %s while backing up", hex(resp.status))
        else:
            logger.info(
                "Backup of %s saved to %s.reg successful ",
                self.current_subkey_path,
                output_path,
            )
            print(f"Backup of {self.current_subkey_path} saved to {output_path}")

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
            logger.debug("Backup option is already activated. Didn't do anything.")
            return
        self.extra_options |= RegOptions.REG_OPTION_BACKUP_RESTORE

        # Log and print
        print("Backup option activated.")
        logger.debug("Backup option activated.")

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

        # Log and print
        print("Backup option deactivated.")
        logger.debug("Backup option deactivated.")

        # Clear the local cache, as the backup option will change the behavior of the registry
        self._clear_all_caches()

    @CLIUtil.addcommand()
    def activate_volatile(self) -> None:
        """
        Set the registry operations to be volatile.
        This means that the registry key will be deleted when the system is restarted.
        """

        self.extra_options |= RegOptions.REG_OPTION_VOLATILE
        self.extra_options &= ~RegOptions.REG_OPTION_NON_VOLATILE
        self.use(self.current_root_path)
        print("Volatile option activated.")

        self._clear_all_caches()

    @CLIUtil.addcommand()
    def disable_volatile(self) -> None:
        """
        Disable the volatile option for the registry operations.
        This means that the registry key will not be deleted when the system is restarted.
        """

        self.extra_options &= ~RegOptions.REG_OPTION_VOLATILE
        self.extra_options |= RegOptions.REG_OPTION_NON_VOLATILE
        self.use(self.current_root_path)
        print("Volatile option deactivated.")
        self._clear_all_caches()

    # --------------------------------------------- #
    #                   Utils
    # --------------------------------------------- #

    def get_handle_on_subkey(
        self,
        subkey_path: PureWindowsPath,
        desired_access_rights: IntFlag | None = None,
    ) -> NDRContextHandle | None:
        """
        Ask the remote server to return an handle on a given subkey.
        If no access rights are specified, it defaults to read access rights.

        :param subkey_path: The subkey path to get a handle on.
        :param desired_access_rights: The desired access rights for the subkey. If None, defaults to read access rights.
        :return: An NDRContextHandle on success, None on failure.
        """

        # If we don't have a root handle, we cannot get a subkey handle
        # This is a safety check, as we should not be able to call this function
        # without having a root handle already set.
        if self._require_root_handles(silent=True):
            return None

        # Convert subkey_path to string and ensure it is null-terminated
        if str(subkey_path) == ".":
            subkey_path = "\x00"
        else:
            subkey_path = str(subkey_path) + "\x00"

        # If no access rights were specified, we use the default read access rights
        if desired_access_rights is None:
            # Default to read access rights
            desired_access_rights = (
                AccessRights.KEY_READ | AccessRights.STANDARD_RIGHTS_READ
            )

        # Log and execute
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

        # Send request
        resp = self.client.sr1_req(req)

        # Check the response status
        if not is_status_ok(resp.status):
            logger.error(
                "Got status %s while getting handle on key",
                hex(resp.status),
            )
            return None

        return resp.phkResult

    def _get_cached_elt(
        self,
        subkey: str | None = None,
        cache_name: str = None,
        desired_access: IntFlag | None = None,
    ) -> NDRContextHandle | CacheElt | None:
        """
        Get a cached element for the specified subkey.

        If the element is not cached, it retrieves the handle on the subkey
        and caches it for future use.

        :param subkey: The subkey path to retrieve. If None, uses the current subkey path.
        :param cache_name: The name of the cache to use. If None, does not use cache.
        :param desired_access: The desired access rights for the subkey. If None, defaults to read access rights.
        :return: A CacheElt object if cache_name is provided, otherwise an NDRContextHandle.
        """

        if self._require_root_handles(silent=True):
            return None

        if desired_access is None:
            # Default to read access rights
            desired_access = AccessRights.KEY_READ | AccessRights.STANDARD_RIGHTS_READ

        # If no specific subkey was specified
        # we use our current subkey path
        if subkey is None or subkey == "" or subkey == ".":
            subkey_path = self.current_subkey_path

        # Otherwise we use the subkey path,
        # the calling parent shall make sure that this path was properly sanitized
        else:
            subkey_path = self._join_path(self.current_subkey_path, subkey)

        # If cache name is specified, we try to use it
        if (
            self.cache.get(cache_name, None) is not None
            and self.cache[cache_name].get(subkey_path, None) is not None
            and self.cache[cache_name][subkey_path].access == desired_access
        ):
            # If we have a cache, we check if the handle is already cached
            # If the access rights are the same, we return the cached elt
            return self.cache[cache_name][subkey_path]

        # Otherwise, we need to get a new handle on the subkey
        handle = self.get_handle_on_subkey(subkey_path, desired_access)
        if handle is None:
            logger.error("Could not get handle on %s", subkey_path)
            return None

        # If we have a cache name, we store the handle in the cache
        cache_elt = CacheElt(handle, desired_access, [])
        if cache_name is not None:
            self.cache[cache_name][subkey_path] = cache_elt

        return cache_elt if cache_name is not None else handle

    def _join_path(
        self, first_path: str | None, second_path: str | None
    ) -> PureWindowsPath:
        """
        Join two paths in a way that is compatible with Windows paths.
        This ensures that the paths are normalized and combined correctly,
        even if they are provided as strings or PureWindowsPath objects.

        :param first_path: The first path to join.
        :param second_path: The second path to join.
        :return: A PureWindowsPath object representing the combined path.
        """

        if first_path is None:
            first_path = ""
        if second_path is None:
            second_path = ""
        if str(PureWindowsPath(second_path).as_posix()).startswith("/"):
            # If the second path is an absolute path, we return it as is
            return PureWindowsPath(
                os.path.normpath(PureWindowsPath(second_path).as_posix()).lstrip("/")
            )
        return PureWindowsPath(
            os.path.normpath(
                os.path.join(
                    PureWindowsPath(first_path).as_posix(),
                    PureWindowsPath(second_path).as_posix(),
                )
            )
        )

    def _require_root_handles(self, silent: bool = False) -> bool:
        """
        Check if we have a root handle set.

        :param silent: If True, do not print any message if no root handle is set.
        :return: True if no root handle is set, False otherwise.
        """

        if self.current_root_handle is None:
            if not silent:
                print("No root key selected ! Use 'use' to use one.")
            return True
        return False

    def _clear_all_caches(self) -> None:
        """
        Clear all caches
        """

        for _, c in self.cache.items():
            c.clear()

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
