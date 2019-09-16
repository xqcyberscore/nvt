##############################################################################
# OpenVAS Vulnerability Test
# $Id: win_guest_account_status.nasl 11532 2018-09-21 19:07:30Z cfischer $
#
# Check value for Accounts: Administrator account status by SID (WMI)
#
# Authors:
# Emanuel Moss <emanuel.moss@greenbone.net>
# Alex Mills <alex.mills@xqcyber.com>
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
  script_oid("1.3.6.1.4.1.25623.1.1.300045");
  script_version("$Revision: 11532 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-21 21:07:30 +0200 (Fri, 21 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-05-04 14:00:00 +0200 (Fri, 04 May 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");
  script_name('Microsoft Windows: Accounts: Guest account status');
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("gb_wmi_access.nasl", "smb_reg_service_pack.nasl");
  script_add_preference(name:"Status", type:"entry", value:"Degraded");
  script_mandatory_keys("Compliance/Launch");
  script_require_keys("WMI/access_successful");
  script_tag(name:"summary", value:"This test checks the setting for policy
'Accounts: Guest account status' on Windows hosts (at least Windows 7).

The policy setting determines whether the Guest account is enabled or disabled.
This account allows unauthenticated network users to gain access to the system by
logging on as a Guest with no password. Unauthorized users can access any
resources that are accessible to the Guest account over the network. That means
that any network shared folders with permissions that allow access to the Guest
account, the Guests group, or the Everyone group will be accessible over the
network. This can lead to the exposure or corruption of data.");
  exit(0);
}

include("smb_nt.inc");
include("policy_functions.inc");

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

title = 'Accounts: Guest account status';

default_guest_username = 'Guest';
guest_sid_suffix = '%-501';
fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Local Policies/Security Options/' + title;

local_var infos, handle, query, res; 

infos = kb_smb_wmi_connectinfo();
if(!infos)
  exit(0);

handle = wmi_connect(host:infos["host"], username:infos["username_wmi_smb"], password:infos["password"]);
if(!handle) {
  policy_logging(text:"WMI Connect to host failed.");
  policy_set_kb(val:"error");
  exit(0);
}

query = "SELECT Status, Name FROM Win32_UserAccount WHERE SID LIKE '" + guest_sid_suffix +  "'"; 
result = wmi_query(wmi_handle:handle, query:query);
wmi_close(wmi_handle:handle);

lines = split(result, keep:FALSE);
fields = split(lines[1],sep:'|', keep:FALSE);

guest_username = fields[1];
guest_status = fields[2];
if( guest_username == '' ){
  policy_logging(text: 'It was unable to determine whether the guest account exists, or is enabled.');
  compliant = 'no';
  value = "Error";
}

if( guest_status == '' ){
  policy_logging(text: 'It was unable to determine whether the guest account exists, or is enabled.');
  compliant = 'no';
  value = "Error";
}

if (tolower(chomp(guest_status)) == 'degraded') {
  policy_logging(text:'The default guest account is disabled.');
  compliant = 'yes';
} else {
  if (tolower(chomp(guest_username)) != 'guest') {
    policy_logging(text:'The default guest account is enabled, but the username has been changed.');
    compliant = 'yes';
  } else {
    policy_logging(text:'The default guest account is enabled, and has the default username.');
    compliant = 'no';
  }
}

policy_add_oid();
policy_set_dval(dval:'Degraded');
policy_fixtext(fixtext:fixtext);
policy_control_name(title:title);
policy_set_kb(val:value);
policy_set_compliance(compliant:compliant);

exit(0);
