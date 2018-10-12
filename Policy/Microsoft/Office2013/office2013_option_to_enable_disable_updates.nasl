##############################################################################
# OpenVAS Vulnerability Test
# $Id: office2013_option_to_enable_disable_updates.nasl 11843 2018-10-11 14:33:21Z emoss $
#
# Check value for Hide option to enable or disable updates
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
  script_oid("1.3.6.1.4.1.25623.1.0.109078");
  script_version("$Revision: 11843 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-11 16:33:21 +0200 (Thu, 11 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-04-17 09:42:28 +0200 (Tue, 17 Apr 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");
  script_name('Microsoft Office: Hide option to enable or disable updates');
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("secpod_ms_office_detection_900025.nasl", "os_detection.nasl");
  script_add_preference(name:"Value", type:"radio", value:"1;0");
  script_mandatory_keys("Compliance/Launch", "Host/runs_windows", "MS/Office/Ver");
  script_tag(name:"summary", value:"This test checks the setting for policy 'Hide option to enable
or disable updates' for Microsoft Office 2013 (at least) on Windows hosts.");
  exit(0);
}

include("smb_nt.inc");
include("policy_functions.inc");
include("host_details.inc");
include("version_func.inc");

cpe = get_app_version(cpe:"cpe:/a:microsoft:office");
if(!cpe){
	policy_logging(text:'Not found at least Microsoft Office 2013 installation.');
	exit(0);
}
office_year = substr(cpe,0,3);

full_version = get_kb_item("MS/Office/Ver");
if(version_is_less(version:full_version, test_version:'15')){
	policy_logging(text:'Not found at least Microsoft Office 2013 installation.');
	exit(0);
}
major_version = substr(full_version,0,3);

title = 'Hide option to enable or disable updates';
fixtext = 'Set following UI path accordingly:
Computer Configuration/Administrative Templates/Microsoft Office ' + office_year + '/(Machine)/Updates/' + title;
type = 'HKLM';
key = 'software\\policies\\microsoft\\office\\' + major_version + '\\common\\officeupdate';
item = 'hideenabledisableupdates';
default = script_get_preference('Value');
value = registry_get_dword(key:key, item:item, type:type);

if(value == ''){
  value = '0';
}

if(value == default){
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