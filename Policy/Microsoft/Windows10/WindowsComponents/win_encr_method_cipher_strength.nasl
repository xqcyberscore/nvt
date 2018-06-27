##############################################################################
# OpenVAS Vulnerability Test
# $Id: win_encr_method_cipher_strength.nasl 10333 2018-06-26 13:47:29Z emoss $
#
# Check value for Choose drive encryption method and cipher strength 
# (Windows 10 [Version 1511] and later)
#
# Authors:
# Emanuel Moss <emanuel.moss@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.109427");
  script_version("$Revision: 10333 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-26 15:47:29 +0200 (Tue, 26 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-06-26 12:48:01 +0200 (Tue, 26 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");
  script_name('Microsoft Windows 10: Drive encryption method and cipher strength (Windows 10)');
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("smb_reg_service_pack.nasl", "os_detection.nasl");
  script_mandatory_keys("Compliance/Launch");
  script_tag(name: "summary", value: "This test checks the setting for policy 
'Choose drive encryption method and cipher strength (Windows 10 [Version 1511] 
and later)' on Windows hosts (at least Windows 10).

The setting configures the algorithm and cipher strength used by BitLocker Drive 
Encryption. 
This policy setting is applied when you turn on BitLocker. 
Changing the encryption method has no effect if the drive is already encrypted, 
or if encryption is in progress.");
  exit(0);
}

include("smb_nt.inc");
include("policy_functions.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  policy_logging(text:'Host is no Microsoft Windows System or it is not possible
to query the registry.');
  exit(0);
}

HostDetails = get_kb_list("HostDetails");
if("cpe:/o:microsoft:windows_10" >!< HostDetails){
  policy_logging(text:'Host is not a Microsoft Windows 10 system. 
This setting applies to Windows 10 systems only.');
  exit(0);
}

title = 'Choose drive encryption method and cipher strength (Windows 10 [Version 1511] and later)';
fixtext = 'Set following UI path accordingly:
Computer Configuration/Administrative Templates/Windows Components/BitLocker Drive Encryption/' + title;
type = 'HKLM';
key = 'Software\\Policies\\Microsoft\\FVE';

OS_item = 'EncryptionMethodWithXtsOs';
OS_value = registry_get_dword(key:key, item:OS_item, type:type);

FD_item = 'EncryptionMethodWithXtsFdv';
FD_value = registry_get_dword(key:key, item:FD_item, type:type);

RD_item = 'EncryptionMethodWithXtsRdv';
RD_value = registry_get_dword(key:key, item:RD_item, type:type);

if(!OS_value){
  OS_value = 'none';
}
if(!FD_value){
  FD_value = 'none';
}
if(!RD_value){
  RD_value = 'none';
}

log = 'Encryption method for operating system drives is set to: ' + OS_value;
log += '\nEncryption method for fixed data drives is set to: ' + FD_value;
log += '\nEncryption method for removable data drives is set to: ' + RD_value;

value = 'OS:' + OS_value;
value += '\nFD:' + FD_value;
value += '\nRD:' + RD_value;

policy_logging_registry(text:log);
policy_set_kb(val:value);
policy_fixtext(fixtext:fixtext);
policy_control_name(title:title);

exit(0);