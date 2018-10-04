##############################################################################
# OpenVAS Vulnerability Test
# $Id: office_lockdown_security.nasl 11729 2018-10-02 14:12:24Z emoss $
#
# Check value for Local Machine Zone Lockdown Security
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
  script_oid("1.3.6.1.4.1.25623.1.0.109653");
  script_version("$Revision: 11729 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-02 16:12:24 +0200 (Tue, 02 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-10-02 15:09:21 +0200 (Tue, 02 Oct 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");
  script_name('Microsoft Office: Local Machine Zone Lockdown Security');
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("secpod_ms_office_detection_900025.nasl", "smb_reg_service_pack.nasl");
  script_add_preference(name:"Office Applications", type:"entry", value:"groove.exe, excel.exe, mspub.exe, powerpnt.exe, pptview.exe, visio.exe, winproj.exe, outlook.exe, spDesign.exe, exprwd.exe, msaccess.exe, onent.exe, mse7.exe");
  script_add_preference(name:"Value", type:"radio", value:"1;0");
  script_mandatory_keys("Compliance/Launch", "MS/Office/Ver");
  script_tag(name:"summary", value:"This test checks the setting for policy 'Local Machine Zone
Lockdown Security' for Microsoft Office 2013 (at least) on Windows hosts.");
  exit(0);
}

include("smb_nt.inc");
include("policy_functions.inc");
include("host_details.inc");
include("version_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  policy_logging(text:'Host is no Microsoft Windows System or it is not possible to query the registry.');
  exit(0);
}

vers = get_app_version(cpe:"cpe:/a:microsoft:office");
if(vers !~ "^201(3|6)"){
	policy_logging(text:'Not found at least Microsoft Office 2013 installation.');
	exit(0);
}

title = 'Local Machine Zone Lockdown Security';
fixtext = 'Set following UI path accordingly:
Computer Configuration/Administrative Templates/Microsoft Office 2016 (Machine)/Security Settings/IE Security/' + title;
type = 'HKLM';
key = 'Software\\microsoft\\internet explorer\\main\\featurecontrol\\feature_localmachine_lockdown';
default = script_get_preference('Value');
compliant = 'yes';
apps = script_get_preference('Office Applications');
app_list = split(apps, sep:',', keep:FALSE);
foreach item (app_list){
	value = registry_get_dword(key:key, item:item, type:type);
	if(value == ''){
	  value = '0';
	}
	if(int(value) != int(default)){
	  compliant = 'no';
	}

	if(item == app_list[0]){
		result = item + ':' + value;
		def = item + ':' + default;
	}else{
		result += ',' + item + ':' + value;
		def += ',' + item + ':' + default;
	}
}

policy_logging(text:'"' + title + '" is set to:\n' + result);
policy_add_oid();
policy_set_dval(dval:def);
policy_fixtext(fixtext:fixtext);
policy_control_name(title:title);
policy_set_kb(val:result);
policy_set_compliance(compliant:compliant);

exit(0);