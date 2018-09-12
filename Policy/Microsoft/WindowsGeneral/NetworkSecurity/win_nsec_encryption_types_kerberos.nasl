##############################################################################
# OpenVAS Vulnerability Test
# $Id: win_nsec_encryption_types_kerberos.nasl 11344 2018-09-12 06:57:52Z emoss $
#
# Check value for Network security: Configure encryption types allowed for Kerberos
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
  script_oid("1.3.6.1.4.1.25623.1.0.109232");
  script_version("$Revision: 11344 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-12 08:57:52 +0200 (Wed, 12 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-06-12 10:28:28 +0200 (Tue, 12 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");
  script_name('Microsoft Windows: Network security: Encryption types allowed for Kerberos');
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("smb_reg_service_pack.nasl");
  script_add_preference(name:"DES-CBC-CRC", type:"radio", value:"Disabled;Enabled");
  script_add_preference(name:"DES-CBC-MD5", type:"radio", value:"Disabled;Enabled");
  script_add_preference(name:"RC4-HMAC", type:"radio", value:"Disabled;Enabled");
  script_add_preference(name:"AES128-CTS-HMAC-SHA1-96", type:"radio", value:"Enabled;Disabled");
  script_add_preference(name:"AES256-CTS-HMAC-SHA1-96", type:"radio", value:"Enabled;Disabled");
  script_add_preference(name:"Future encryption types", type:"radio", value:"Enabled;Disabled");
  script_mandatory_keys("Compliance/Launch");
  script_tag(name:"summary", value:"This test checks the setting for policy
'Network security: Configure encryption types allowed for Kerberos' on Windows
hosts (at least Windows 7).

The policy setting controls the encryption types that the Kerberos protocol is
allowed to use. If not selected, the encryption type will not be allowed. The
setting might affect compatibility with client computers or services and
applications.");
  exit(0);
}

include("smb_nt.inc");
include("policy_functions.inc");
include("byte_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  policy_logging(text:'Host is no Microsoft Windows System or it is not possible
to query the registry.');
  exit(0);
}

if(get_kb_item("SMB/WindowsVersion") < "6.1"){
  policy_logging(text:'Host is not at least a Microsoft Windows 7 system.
Older versions of Windows are not supported any more. Please update the
Operating System.');
  exit(0);
}

FutureEncryptionTypes = script_get_preference('Future encryption types');
AES256 = script_get_preference('AES256-CTS-HMAC-SHA1-96');
AES128 = script_get_preference('AES128-CTS-HMAC-SHA1-96');
RC4HMAC = script_get_preference('RC4-HMAC');
MD5 = script_get_preference('DES-CBC-MD5');
CRC = script_get_preference('DES-CBC-CRC');

if(FutureEncryptionTypes == 'Enabled'){
  default += 'Future encryption types';
  bin = '11111111111111111111111111';
}else{
  bin = '0';
}
if(AES256 == 'Enabled'){
  default += ';AES256-CTS-HMAC-SHA1-96';
  bin += '1';
}else{
  bin += '0';
}
if(AES128 == 'Enabled'){
  default += ';AES128-CTS-HMAC-SHA1-96';
  bin += '1';
}else{
  bin += '0';
}
if(RC4HMAC == 'Enabled'){
  default += ';RC4-HMAC';
  bin += '1';
}else{
  bin += '0';
}
if(MD5 == 'Enabled'){
  default += ';ADES-CBC-MD5';
  bin += '1';
}else{
  bin += '0';
}
if(CRC == 'Enabled'){
  default += ';DES-CBC-CRC';
  bin += '1';
}else{
  bin += '0';
}

title = 'Network security: Configure encryption types allowed for Kerberos';
fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Local Policies/Security Options/' + title;
type = 'HKLM';
key = 'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters';
item = 'SupportedEncryptionTypes';
def = bin2dec(bin:bin);
value = registry_get_dword(key:key, item:item, type:type);
if(value == ''){
  value = '0';
}

if(int(value) == int(def)){
  compliant = 'yes';
}else{
  compliant = 'no';
}

policy_logging(text:'"' + title + '" is set to: ' + value);
policy_add_oid();
policy_set_dval(dval:default);
policy_fixtext(fixtext:fixtext);
policy_control_name(title:title);
policy_set_kb(val:value);
policy_set_compliance(compliant:compliant);

exit(0);