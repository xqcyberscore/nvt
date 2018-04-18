##############################################################################
# OpenVAS Vulnerability Test
# $Id: office2013_document_manifest.nasl 9512 2018-04-17 14:08:25Z emoss $
#
# Check value for Disable Smart Document's use of manifests
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
  script_oid("1.3.6.1.4.1.25623.1.0.109059");
  script_version("$Revision: 9512 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-17 16:08:25 +0200 (Tue, 17 Apr 2018) $");
  script_tag(name:"creation_date", value:"2018-04-16 09:42:28 +0200 (Mon, 16 Apr 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");
  script_name('Microsoft Office 2013: Disable Smart Documents use of manifests');
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("secpod_ms_office_detection_900025.nasl");
	script_require_keys("MS/Office/Ver");
  script_mandatory_keys("Compliance/Launch");
  script_tag(name: "summary", value: 'Check Setting "Disable Smart Documents use of manifests" (Microsoft Office 2013).');
  exit(0);
}

include("smb_nt.inc"); 
include("policy_functions.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  policy_logging(text:'Host is no Microsoft Windows System or it is not possible
to query the registry.');
  exit(0);
}

Office_Ver = get_kb_item("MS/Office/Ver");
if(ereg(string:Office_Ver, pattern:"^15.0") != 1){
  policy_logging(text:'Unable to find Microsoft Office 2013 on Host System.');
  exit(0);
}

key = 'Software\\Policies\\Microsoft\\Office\\common\\Smart Tag';
value = registry_get_dword(key:key, item:'NeverLoadManifests', type:'HKCU');
if( value == ''){
  policy_logging(text:'Unable to detect registry value "HKCU\\Software\\Policies\\Microsoft\\Office\\common\\Smart Tag!NeverLoadManifests".');
  set_kb_item(name:'Policy/MS/Office2013/NeverLoadManifests', value:'none');
}else{
  policy_logging(text:'Registry value "HKCU\\Software\\Policies\\Microsoft\\Office\\common\\Smart Tag!NeverLoadManifests" is set to: ' + value);
  set_kb_item(name:'Policy/MS/Office2013/NeverLoadManifests', value:value);
}

exit(0);