"""
DCE/RPC client
"""

import socket
import os
import pathlib
from typing import Optional, NoReturn

from scapy.layers.msrpce.all import *
from scapy.layers.msrpce.raw.ms_samr import *
from scapy.layers.msrpce.raw.ms_rrp import *
from scapy.layers.dcerpc import RPC_C_AUTHN_LEVEL
from scapy.utils import (
    CLIUtil,
    pretty_list,
    human_size,
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
from scapy.layers.kerberos import KerberosSSP

from pathlib import PureWindowsPath

conf.color_theme = DefaultTheme()


KEY_QUERY_VALUE = 0x00000001
KEY_ENUMERATE_SUB_KEYS = 0x00000008
MAX_ALLOWED = 0x02000000
ERROR_NO_MORE_ITEMS = 0x00000103
ERROR_SUBKEY_NOT_FOUND = 0x000006F7

# Predefined keys
HKEY_CLASSES_ROOT = "HKCROOT"  # Registry entries subordinate to this key define types (or classes) of documents and the properties associated with those types. The subkeys of the HKEY_CLASSES_ROOT key are a merged view of the following two subkeys:
HKEY_CURRENT_USER = "HKCU"  # Registry entries subordinate to this key define the preferences of the current user. These preferences include the settings of environment variables, data on program groups, colors, printers, network connections, and application preferences. The HKEY_CURRENT_USER root key is a subkey of the HKEY_USERS root key, as described in section 3.1.1.8.
HKEY_LOCAL_MACHINE = "HKLM"  # Registry entries subordinate to this key define the physical state of the computer, including data on the bus type, system memory, and installed hardware and software.
HKEY_CURRENT_CONFIG = "HKC"  # This key contains information on the current hardware profile of the local computer. HKEY_CURRENT_CONFIG is an alias for HKEY_LOCAL_MACHINE\System\CurrentControlSet\Hardware Profiles\Current
HKEY_USERS = "HKU"
HKEY_PERFORMANCE_DATA = "HKPERFORMANCE"  # Registry entries subordinate to this key allow access to performance data.
HKEY_PERFORMANCE_TEXT = ""  # Registry entries subordinate to this key reference the text strings that describe counters in U.S. English.
HKEY_PERFORMANCE_NLSTEXT = ""  # Registry entries subordinate to this key reference the text strings that describe counters in the local language of the area in which the computer is running.

AVAILABLE_ROOT_KEYS: list[str] = [
    HKEY_LOCAL_MACHINE,
    HKEY_CURRENT_USER,
    HKEY_USERS,
    HKEY_CLASSES_ROOT,
    HKEY_CURRENT_CONFIG,
    HKEY_PERFORMANCE_DATA,
    HKEY_PERFORMANCE_TEXT,
    HKEY_PERFORMANCE_NLSTEXT,
]


@conf.commands.register
class regclient(CLIUtil):
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

        self.client.verb = False
        self.client.connect(target)
        self.client.open_smbpipe("winreg")
        self.client.bind(self.interface)
        self.ls_cache: dict[str:list] = dict()
        self.cat_cache: dict[str:list] = dict()
        self.root_handle = {}
        self.current_root_handle = None
        self.current_subkey_handle = None
        self.current_subkey_path: PureWindowsPath = pathlib.PureWindowsPath("")
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

    @CLIUtil.addcommand()
    def use(self, root_path):
        """
        Use base key (HKLM, HKCU, etc.)
        """
        print(f">{root_path}<")
        if root_path.upper().startswith(HKEY_CLASSES_ROOT):
            # Change to HKLM root
            self.current_root_handle = self.root_handle.setdefault(
                HKEY_CLASSES_ROOT,
                self.client.sr1_req(
                    OpenClassesRoot_Request(
                        ServerName=None,
                        samDesired=KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS,
                    ),
                    timeout=10,
                ).phKey,
            )
            self.current_root_path = HKEY_CLASSES_ROOT

        if root_path.upper().startswith(HKEY_LOCAL_MACHINE):
            # Change to HKLM root
            self.current_root_handle = self.root_handle.setdefault(
                HKEY_LOCAL_MACHINE,
                self.client.sr1_req(
                    OpenLocalMachine_Request(
                        ServerName=None,
                        samDesired=KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS,
                    ),
                    timeout=6,
                ).phKey,
            )
            self.current_root_path = HKEY_LOCAL_MACHINE

        if root_path.upper().startswith(HKEY_CURRENT_USER):
            # Change to HKLM root
            self.current_root_handle = self.root_handle.setdefault(
                HKEY_CURRENT_USER,
                self.client.sr1_req(
                    OpenCurrentUser_Request(
                        ServerName=None,
                        samDesired=KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS,
                    ),
                    timeout=4,
                ).phKey,
            )
            self.current_root_path = HKEY_CURRENT_USER

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

    @CLIUtil.addcommand()
    def version(self):
        """
        Get remote registry server version
        """
        version = self.client.sr1_req(
            BaseRegGetVersion_Request(hKey=self.current_root_handle)
        ).lpdwVersion
        print(f"Remote registry server version: {version}")

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
            if resp.status == ERROR_NO_MORE_ITEMS:
                break
            elif resp.status:
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
    def cat(self, folder: Optional[str] = None) -> list[str]:
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
        while True:
            req = BaseRegEnumValue_Request(
                hKey=handle,
                dwIndex=idx,
                lpValueNameIn=RPC_UNICODE_STRING(MaximumLength=1024),
                lpData=b" " * 1024,
                lpcbData=1024,
                lpcbLen=1024,
            )

            resp = self.client.sr1_req(req)
            if resp.status == ERROR_NO_MORE_ITEMS:
                break
            elif resp.status:
                print(
                    f"[-] Error : got status {hex(resp.status)} while enumerating values"
                )
                breakpoint()
                self.cat_cache.clear()
                return []

            breakpoint()
            self.ls_cache[subkey_path].append(
                resp.lpNameOut.valueof("Buffer").decode("utf-8").strip("\x00")
            )
            idx += 1

    def _require_root_handles(self, silent: bool = False) -> bool:
        if self.current_root_handle is None:
            if not silent:
                print("No root key selected ! Use 'use' to use one.")
            return True

    @CLIUtil.addcommand()
    def dev(self) -> NoReturn:
        """
        Joker function to jump into the python code for dev purpose
        """
        breakpoint()

    @CLIUtil.addcommand(spaces=True)
    def cd(self, subkey: str) -> NoReturn:
        """
        Change current subkey path
        """
        self.current_subkey_path = self._join_path(self.current_subkey_path, subkey)
        self.current_subkey_handle = self.get_handle_on_subkey(self.current_subkey_path)
        self.ls_cache.clear()

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

    def get_handle_on_subkey(self, subkey_path: PureWindowsPath) -> NDRContextHandle:
        """
        Ask the remote server to return an handle on a given subkey
        """
        if str(subkey_path) == ".":
            subkey_path = "\x00"
        else:
            subkey_path = str(subkey_path) + "\x00"

        # print(f"getting handle on: {subkey_path}")
        req = BaseRegOpenKey_Request(
            hKey=self.current_root_handle,
            lpSubKey=RPC_UNICODE_STRING(Buffer=subkey_path),
            samDesired=KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS,
        )
        resp = self.client.sr1_req(req)
        if resp.status == ERROR_SUBKEY_NOT_FOUND:
            print(f"[-] Error : got status {hex(resp.status)} while enumerating keys")
            return None

        return resp.phkResult

    def _join_path(self, first_path: str, second_path: str) -> PureWindowsPath:
        return PureWindowsPath(
            os.path.normpath(
                os.path.join(
                    PureWindowsPath(first_path).as_posix(),
                    PureWindowsPath(second_path).as_posix(),
                )
            )
        )


def main():
    """
    Main entry point
    """
    from scapy.utils import AutoArgparse

    AutoArgparse(regclient)


if __name__ == "__main__":
    from scapy.utils import AutoArgparse

    AutoArgparse(regclient)
