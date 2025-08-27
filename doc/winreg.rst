#############
WinReg
#############

The `scapy-winreg` module allows interaction with the Windows Registry over SMB using the MS-RRP protocol.
It supports various operations such as listing subkeys, reading and writing values, creating and deleting keys, and more.

********************
Some vocabulary
********************

In the context of the Windows Registry, it's important to understand the following terms:

* **Root key**: A root key, also called hive, is a container object in the registry that can hold subkeys and values. It's a key of the highest hierarchical level.
* **Subkey**: A subkey is a key that is nested within another key. It can also contain its own subkeys and values.
* **Key**: A key is a container object in the registry that can hold subkeys and values. It can designate both a root key and a subkey.
* **Value**: A value is a named item containing data and attached to a key. Each value has a name, a data type, and the actual data. Common data types include strings (REG_SZ), binary data (REG_BINARY), and DWORDs (REG_DWORD).

********************
Key functionnalities
********************

===================================
``use``: Select a root registry key
===================================

The ``use`` function allows you to select a root registry key to work with. 
The available root keys are:

* HKEY_CLASSES_ROOT (**HKCR**)
* HKEY_LOCAL_MACHINE (**HKLM**)
* HKEY_CURRENT_USER (**HKCU**)
* HKEY_USERS (**HKU**)
* HKEY_CURRENT_CONFIG (**HKCC**)
* HKEY_PERFORMANCE_DATA (**HKPD**)
* HKEY_PERFORMANCE_NLSTEXT (**HKPN**)
* HKEY_PERFORMANCE_TEXT (**HKPT**)

.. code-block:: bash
    :caption: CLI usage example

    >>> [reg] CHOOSE ROOT KEY\. > use HKLM
    >>> [reg] HKLM\. >

.. code-block:: bash
    :caption: Direct request from the command line

    >>> scapy-winreg  --UPN Administrator@DOM.LOCAL --password Passw0rd 10.0.0.10 --rootKey HKLM
    >>> [reg] HKLM\. >

====================
``ls``: List subkeys
====================

The ``ls`` function lists the subkeys of the current key or a specified relative key.

.. code-block:: bash
    :caption: CLI usage example

    >>> [reg] HKLM\. > ls
    Subkeys:
    SOFTWARE
    SYSTEM
    SAM
    SECURITY
    HARDWARE
    BCD00000000
    ...
    >>> [reg] HKLM\. > ls SYSTEM\CurrentControlSet\Services
    Subkeys:
    AdobeARMservice
    AFD
    ALG
    AppIDSvc
    Appinfo
    AppMgmt
    ...

=============================
``cd``: Change current subkey
=============================

The ``cd`` function changes the current subkey to a specified relative key or to the root of the current root key.

.. code-block:: bash
    :caption: CLI usage example

    >>> [reg] HKLM\. > cd SYSTEM\CurrentControlSet\Services
    >>> [reg] HKLM\SYSTEM\CurrentControlSet\Services > cd ..
    >>> [reg] HKLM\SYSTEM\CurrentControlSet > cd \
    >>> [reg] HKLM\. > cd /SOFTWARE/Microsoft/Windows
    >>> [reg] HKLM\SOFTWARE\Microsoft\Windows > cd /
    >>> [reg] HKLM\. >

.. code-block:: bash
    :caption: Direct request from the command line

    >>> scapy-winreg  --UPN Administrator@DOM.LOCAL --password Passw0rd 10.0.0.10 --rootKey HKLM --subKey SYSTEM/CurrentControlSet/Services/winmgmt
    >>> [reg] HKLM\SYSTEM\CurrentControlSet\Services\winmgmt >

================================
``cat``: Display values of a key
================================

The ``cat`` function displays the values of the current key or a specified relative key.

.. code-block:: bash
    :caption: CLI usage example

    >>> [reg] HKLM\. > cat
    Values:
    (Default)    REG_SZ    (value not set)
    Class        REG_SZ    (value not set)
    LastWriteTime    REG_QWORD    132537600000000000
    ...
    >>> [reg] HKLM\SYSTEM\CurrentControlSet\Services\winmgmt > cat
  - DependOnService     (REG_MULTI_SZ - 7) RPCSS

  - Description         (REG_SZ - 1)    @%Systemroot%\system32\wbem\wmisvc.dll,-204
  - DisplayName         (REG_SZ - 1)    @%Systemroot%\system32\wbem\wmisvc.dll,-205
  - ErrorControl        (REG_DWORD - 4) 0
  - FailureActions      (REG_BINARY - 3) b'\x80Q\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x14\x00\x00\x00\x01\x00\x00\x00\xc0\xd4\x01\x00\x01\x00\x00\x00\xe0\x93\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00'
  - ImagePath           (REG_EXPAND_SZ - 2) %systemroot%\system32\svchost.exe -k netsvcs -p
  - ObjectName          (REG_SZ - 1)    localSystem
  - ServiceSidType      (REG_DWORD - 4) 1
  - Start               (REG_DWORD - 4) 2
  - SvcMemHardLimitInMB (REG_DWORD - 4) 28
  - SvcMemMidLimitInMB  (REG_DWORD - 4) 20
  - SvcMemSoftLimitInMB (REG_DWORD - 4) 11
  - Type                (REG_DWORD - 4) 32
  -                     (REG_SZ - 1)    This is the default value


Notice how the default value is represented with an empty name, when regedit shows it as "(Default)".
This is a design choice to avoid confusion with a value that would actually be named "(Default)".
Future development may include an option to display it as "(Default)" for better user experience.


=======================================
``query_info``: Get subkey information
=======================================

The ``query_info`` function retrieves information about the current key or a specified relative key, including the number of subkeys, number of values, and last write time.

.. code-block:: bash
    :caption: CLI usage example

    >>> [reg] HKLM\SYSTEM\CurrentControlSet\Services\winmgmt > query_info
        Info on key:
          - Number of subkeys: 1
          - Length of the longest subkey name (in bytes): 20
          - Number of values: 14
          - Length of the longest value name (in bytes): 38
          - Last write time: 2025-08-27 15:20:54

=============================================
``version``: Get the remote registry version
=============================================

.. code-block:: bash
    :caption: CLI usage example

    >>> [reg] HKLM\SYSTEM\CurrentControlSet\Services\winmgmt > version
        Remote registry server version: 6

========================================
``get_sd``: Get security descriptor
========================================

The ``get_sd`` function retrieves the security descriptor of the current key or a specified relative key.
The information is displayed in a kindof human-readable format. Yet, information displayed is currently incomplete.
Upcoming versions will provide a more complete and user-friendly output.

.. code-block:: bash
    :caption: CLI usage example

    >>> [reg] HKLM\. > get_sd SAM
        Owner: S-1-5-32-544
        Group: S-1-5-18
        DACL:
         -  (A;CI;;;;S-1-5-32-545)
         -  (A;CI;;;;S-1-5-32-544)
         -  (A;CI;;;;S-1-5-18)
         -  (A;CI;;;;S-1-3-0)
         -  (A;CI;;;;S-1-15-2-1)
         -  (A;CI;;;;S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681)