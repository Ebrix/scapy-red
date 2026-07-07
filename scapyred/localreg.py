# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy RED
# See https://scapy.net/ for more information
# Copyright (C) github/Ebrix

r"""
Offline Windows Registry hive browser.

``scapy-localreg`` is the local, read-only counterpart to
:mod:`scapyred.winreg`: instead of driving a live host over MS-RRP, it opens a
saved hive file (the ``.reg`` files produced by
:meth:`scapyred.winreg.RegClient.save`, or on-disk ``SAM`` / ``SECURITY`` /
``SYSTEM`` / ``SOFTWARE`` / ``NTUSER.DAT`` hives) and lets you browse it with
the same commands and output as the remote client - ``ls``, ``cat``, ``cd``,
``query_info``, ``get_sd`` and ``exploration_mode``. When ``cat`` prints a
binary value that is actually a self-relative security descriptor, it also
shows the decoded ACL inline.

The REGF on-disk decoding lives in :mod:`scapyred.regf`; this module is only
the :class:`scapy.utils.CLIUtil` front-end. A loaded hive's *root node is the
browse root* (one hive per client), e.g. a ``SAM.reg`` saved from ``HKLM\SAM``
presents its keys directly under ``\``.

Because everything is served from a local file, there is no per-key round trip
to amortize, so - unlike the remote client - this browser keeps no handle/value
cache: every command re-reads straight from the mapped hive.

.. note::
   A few helpers here (``_join_path``, ``_filetime_to_str``) are intentionally
   close copies of :class:`scapyred.winreg.RegClient`. They are prime
   candidates for a future shared base module factored out of both clients;
   that extraction is deliberately deferred until this browser has settled.
"""

import logging
import os

from datetime import datetime, timezone
from pathlib import PureWindowsPath

from scapy.config import conf
from scapy.error import log_runtime
from scapy.themes import DefaultTheme, NoTheme
from scapy.utils import CLIUtil
from scapy.layers.windows.registry import RegEntry, RegType
from scapy.layers.windows.security import SECURITY_DESCRIPTOR

from scapyred.regf import RegistryHive


def _filetime_to_str(filetime: int) -> str:
    """
    Convert a raw 64-bit FILETIME (100ns intervals since 1601-01-01) to a
    human readable UTC date, or ``"N/A"`` when unset.
    """
    if not filetime:
        return "N/A"
    seconds = (filetime - 116444736000000000) // 10000000
    return datetime.fromtimestamp(seconds, tz=timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S"
    )


def _as_security_descriptor(data: bytes) -> SECURITY_DESCRIPTOR | None:
    r"""
    Best-effort decode of a raw value that looks like a security descriptor.

    A self-relative ``SECURITY_DESCRIPTOR`` starts with ``Revision=1``,
    ``Sbz1=0`` and a little-endian ``Control`` word carrying the
    ``SE_SELF_RELATIVE`` (0x8000) bit - i.e. the tell-tale ``\x01\x00..\x80``
    prefix, most commonly ``\x01\x00\x04\x80`` (self-relative + DACL present).
    Windows stores these blobs in plain ``REG_BINARY`` / ``REG_NONE`` values
    (e.g. a service's ``Security`` value), so it is handy to surface the
    decoded ACL right next to the raw bytes.

    :return: the parsed descriptor, or ``None`` if ``data`` does not look like
        (or does not parse as) one.
    """
    if not isinstance(data, bytes) or len(data) < 20:
        return None
    if data[0] != 1 or data[1] != 0:  # Revision / Sbz1
        return None
    control = data[2] | (data[3] << 8)
    if not control & 0x8000:  # SE_SELF_RELATIVE
        return None
    try:
        return SECURITY_DESCRIPTOR(data)
    except Exception:
        return None


@conf.commands.register
class RegHiveClient(CLIUtil):
    r"""
    A simple offline registry hive browser.

    :param target: path to the hive file (``.reg`` / ``SAM`` / ``SYSTEM`` ...)
                   to open.
    :param subKey: the subkey to start in (default None, root of the hive).
    :param color: emit ANSI colors in the output; pass ``--no-color`` on the
                  CLI to turn this off.
    :param cli: CLI mode (default True). False to use for scripting.
    :param debug: set > 0 for debug logging.
    """

    def __init__(
        self,
        target: str,
        subKey: str = None,
        color: bool = True,
        cli: bool = True,
        debug: int = 0,
    ) -> None:
        if debug:
            log_runtime.setLevel(logging.DEBUG)

        # Colors go through Scapy's global color theme (like samhive /
        # securityhive), so ``sd.show_print()`` and the rest stay consistent.
        conf.color_theme = DefaultTheme() if color else NoTheme()

        self.hive = RegistryHive(target)
        self.root = self.hive.root_key()
        self.hive_name = os.path.basename(target)

        # Current position in the hive: the key node we are "in" and its path
        # from the root. These are plain state, not a cache.
        self.current_nk = self.root
        self.current_subkey_path: PureWindowsPath = PureWindowsPath("")

        # When True, ``cd`` also dumps subkeys + values of the destination.
        self.expl_mode = False

        if subKey:
            self.cd(subKey.strip())
        if cli:
            self.loop(debug=debug)

    def ps1(self) -> str:
        return f"[hive:{self.hive_name}] \\{self.current_subkey_path} > "

    @CLIUtil.addcommand()
    def close(self) -> None:
        """
        Close the hive file
        """
        print("Hive closed")
        self.hive.close()

    @CLIUtil.addcommand()
    def load(self, target: str) -> None:
        """
        Close the current hive and open another one.

        :param target: path to the hive file to open.
        """
        self.hive.close()
        self.hive = RegistryHive(target)
        self.root = self.hive.root_key()
        self.hive_name = os.path.basename(target)
        self.current_nk = self.root
        self.current_subkey_path = PureWindowsPath("")
        print(f"Loaded hive {self.hive_name}")

    # --------------------------------------------- #
    #                   List and Cat
    # --------------------------------------------- #

    @CLIUtil.addcommand(mono=True)
    def ls(self, subkey: str | None = None) -> list[str]:
        """
        Enumerate the subkeys of the given relative `subkey`

        :param subkey: the relative subkey to enumerate the subkeys from.
                       If None, uses the current subkey path.

        :return: the list of the subkey names.
        """
        nk = self._resolve(subkey)
        if nk is None:
            log_runtime.error("No such subkey: %s", subkey)
            return []
        return [sub.name_str() for sub in self.hive.subkeys(nk)]

    @CLIUtil.addoutput(ls)
    def ls_output(self, results: list[str]) -> None:
        """
        Print the output of 'ls'
        """
        ct = conf.color_theme
        for subkey in results:
            # Subkeys are containers: show them blue, like directories.
            print(ct.blue(subkey))

    @CLIUtil.addcomplete(ls)
    def ls_complete(self, subkey: str) -> list[str]:
        """
        Auto-complete ls
        """
        subkey = subkey.strip().replace("/", "\\")
        if "\\" in subkey:
            parent, _, subkey = subkey.rpartition("\\")
        else:
            parent = ""

        return [
            str(self._join_path(parent, name))
            for name in self.ls(parent)
            if name.lower().startswith(subkey.lower())
        ]

    @CLIUtil.addcommand(mono=True)
    def cat(self, subkey: str | None = None) -> list[RegEntry]:
        """
        Enumerate and retrieve the registry values for a given subkey path.

        :param subkey: the relative subkey path to enumerate.
            If None, uses the current subkey path.

        :return: a list of registry entries (as RegEntry objects) for the
            specified subkey path.
        """
        nk = self._resolve(subkey)
        if nk is None:
            log_runtime.error("No such subkey: %s", subkey)
            return []
        return [self._to_regentry(vk) for vk in self.hive.values(nk)]

    @CLIUtil.addoutput(cat)
    def cat_output(self, results: list[RegEntry]) -> None:
        """
        Print the output of 'cat'
        """
        if not results:
            print("No values found.")
            return

        ct = conf.color_theme
        for entry in results:
            # UNK carries the original (unknown) type id in ``real_value``.
            type_id = (
                entry.reg_type.real_value
                if entry.reg_type == RegType.UNK
                else entry.reg_type.value
            )
            # Pad on the plain text, then colorize, so columns stay aligned
            # regardless of the ANSI escapes.
            if entry.reg_name == "":
                name = ct.blue(ct.bold("(Default)".ljust(24)))
            else:
                name = ct.green(entry.reg_name.strip().ljust(24))
            reg_type = ct.cyan(f"({entry.reg_type.name} - {type_id})".ljust(24))
            print(f"  - {name} {reg_type} {entry.reg_data}")

            # Binary blobs are often self-relative security descriptors; if so,
            # show the decoded ACL underneath the raw value.
            if entry.reg_type in (RegType.REG_NONE, RegType.REG_BINARY):
                sd = _as_security_descriptor(entry.reg_data)
                if sd is not None:
                    print(f"      {ct.yellow('|_ inferred security descriptor:')}")
                    for line in sd.show(dump=True).rstrip().splitlines():
                        print("      " + line)

    @CLIUtil.addcomplete(cat)
    def cat_complete(self, subkey: str) -> list[str]:
        """
        Auto-complete cat
        """
        return self.ls_complete(subkey)

    # --------------------------------------------- #
    #                   Change Directory
    # --------------------------------------------- #

    @CLIUtil.addcommand(mono=True)
    def cd(self, subkey: str) -> None:
        """
        Change current subkey path

        :param subkey: the relative subkey to go to.
        """
        if subkey.strip() == "":
            path, nk = PureWindowsPath(""), self.root
        else:
            path = self._join_path(self.current_subkey_path, subkey)
            nk = self._nk_for_path(path)

        if nk is None:
            log_runtime.error("Could not change directory to %s", subkey)
            raise ValueError(f"Could not change directory to {subkey}")

        self.current_subkey_path = path
        self.current_nk = nk

        if self.expl_mode:
            # Return a value so the @addoutput hook (cd_output) fires.
            return f"[{self.hive_name}:\\{self.current_subkey_path}]"

    @CLIUtil.addcomplete(cd)
    def cd_complete(self, subkey: str) -> list[str]:
        """
        Auto-complete cd
        """
        return self.ls_complete(subkey)

    @CLIUtil.addoutput(cd)
    def cd_output(self, pwd) -> None:
        """
        Print the output of 'cd' (only in exploration mode)
        """
        if self.expl_mode and pwd is not None:
            ct = conf.color_theme
            print(ct.bold(pwd))
            print(ct.cyan("---------- SubKeys ----------"))
            self.ls_output(self.ls())
            print(ct.cyan("---------- Values -----------"))
            self.cat_output(self.cat())

    @CLIUtil.addcommand()
    def exploration_mode(self) -> None:
        """
        Activate / Deactivate exploration mode: perform ls and cat
        automatically when changing directory
        """
        self.expl_mode = not self.expl_mode
        print("Exploration mode " + ("activated" if self.expl_mode else "disabled"))

    # --------------------------------------------- #
    #                   Get Information
    # --------------------------------------------- #

    @CLIUtil.addcommand(mono=True)
    def query_info(self, subkey: str | None = None):
        """
        Query information on the current subkey

        :param subkey: the relative subkey to query info from. If None,
            it uses the current subkey path.

        :return: the key node (NK_Record) for the subkey, or None.
        """
        nk = self._resolve(subkey)
        if nk is None:
            log_runtime.error("Could not get the specified subkey.")
        return nk

    @CLIUtil.addoutput(query_info)
    def query_info_output(self, nk) -> None:
        """
        Print the output of 'query_info'
        """
        if nk is None:
            print("No information found.")
            return
        ct = conf.color_theme
        print()
        print(ct.bold("Info on key:"))
        for label, value in [
            ("Number of subkeys", nk.num_subkeys),
            ("Longest subkey name (bytes)", nk.largest_subkey_name_len),
            ("Number of values", nk.num_values),
            ("Longest value name (bytes)", nk.largest_value_name_len),
            ("Last write time", _filetime_to_str(nk.last_written)),
            ("Class", self.hive.class_name(nk)),
        ]:
            print(f"  - {ct.cyan(label)}: {value}")
        print()

    @CLIUtil.addcomplete(query_info)
    def query_info_complete(self, subkey: str) -> list[str]:
        """
        Auto complete subkeys for `query_info`
        """
        return self.ls_complete(subkey)

    @CLIUtil.addcommand(mono=True)
    def get_sd(self, subkey: str | None = None) -> SECURITY_DESCRIPTOR | None:
        """
        Get the security descriptor of the current subkey.

        :param subkey: the relative subkey to get the security descriptor from.
            If None, it uses the current subkey path.

        :return: the SECURITY_DESCRIPTOR object if all went well. None otherwise.
        """
        nk = self._resolve(subkey)
        if nk is None:
            return None
        sk = self.hive.security(nk)
        if sk is None:
            return None
        return SECURITY_DESCRIPTOR(sk.descriptor)

    @CLIUtil.addoutput(get_sd)
    def get_sd_output(self, sd: SECURITY_DESCRIPTOR | None) -> None:
        """
        Print the output of 'get_sd'
        """
        if sd is None:
            print("No security descriptor found.")
        else:
            # show_print() honors conf.color_theme, set from our ``color`` flag.
            sd.show_print()

    @CLIUtil.addcomplete(get_sd)
    def get_sd_complete(self, subkey: str) -> list[str]:
        """
        Auto complete subkeys for `get_sd`
        """
        return self.ls_complete(subkey)

    # --------------------------------------------- #
    #                   Utils
    # --------------------------------------------- #

    def _resolve(self, subkey: str | None):
        """
        Return the key node for a relative ``subkey``, or the current one.

        :param subkey: a path relative to the current key. ``None`` / ``""`` /
            ``"."`` mean "the current key".

        :return: the resolved ``NK_Record``, or ``None`` if it does not exist.
        """
        if subkey is None or subkey in ("", "."):
            return self.current_nk
        path = self._join_path(self.current_subkey_path, subkey)
        return self._nk_for_path(path)

    def _nk_for_path(self, path: PureWindowsPath):
        """Walk the subkey lists from the root down to the key node at ``path``."""
        nk = self.root
        for part in path.parts:
            nk = next(
                (
                    sub
                    for sub in self.hive.subkeys(nk)
                    if sub.name_str().casefold() == part.casefold()
                ),
                None,
            )
            if nk is None:
                return None
        return nk

    def _join_path(
        self, first_path: str | None, second_path: str | None
    ) -> PureWindowsPath:
        """
        Join two paths in a Windows-compatible way, so that ``..`` and a
        leading backslash (absolute-from-root) navigation both work.
        """
        first = PureWindowsPath(first_path or "").as_posix()
        second = PureWindowsPath(second_path or "").as_posix()
        if second.startswith("/"):
            # Absolute from the hive root: ignore the current path.
            return PureWindowsPath(os.path.normpath(second).lstrip("/"))
        return PureWindowsPath(os.path.normpath(os.path.join(first, second)))

    def _to_regentry(self, vk) -> RegEntry:
        """Decode a ``vk`` record into a :class:`RegEntry` (like the remote client)."""
        name = vk.name_str()
        data = self.hive.value_data(vk)
        reg_type = RegType(int(vk.data_type))
        try:
            return RegEntry.frombytes(name, reg_type, data)
        except Exception:
            # Malformed / truncated data for the declared type: fall back to
            # raw bytes rather than dropping the value entirely.
            return RegEntry(name, RegType.REG_BINARY, data)


def main():
    """
    Main entry point
    """
    from scapy.utils import AutoArgparse

    AutoArgparse(RegHiveClient)


if __name__ == "__main__":
    main()
