##############################################################################
# OpenVAS Vulnerability Test
# $Id: win_telemetry_proxy_server.nasl 11387 2018-09-14 12:19:57Z emoss $
#
# Check value for Configure Authenticated Proxy usage for the Connected
# User Experience and Telemetry service
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
  script_oid("1.3.6.1.4.1.25623.1.0.109610");
  script_version("$Revision: 11387 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-14 14:19:57 +0200 (Fri, 14 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-09-14 12:00:44 +0200 (Fri, 14 Sep 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");
  script_name('Microsoft Windows: Configure Connected User Experiences and Telemetry');
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("smb_reg_service_pack.nasl", "os_detection.nasl");
  script_add_preference(name:"Proxy", type:"entry", value:"None");
  script_mandatory_keys("Compliance/Launch");
  script_tag(name:"summary", value:"This test checks the setting for policy
'Configure Connected User Experiences and Telemetry' on Windows hosts (at least Windows 10).

The policy setting it is possible to forward Connected User Experience and Telemetry requests to a
proxy server. If enabled, this policy setting specifies the FQDN or IP address of the destination
device within an organizations network (and optionally a port number, if desired).");
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

title = 'Configure Connected User Experiences and Telemetry';
fixtext = 'Set following UI path accordingly:
Computer Configuration/Administrative Templates/Windows Components/Data Collection and Preview Builds/' + title;
type = 'HKLM';
key = 'Software\\Policies\\Microsoft\\Windows\\DataCollection';
item = 'TelemetryProxyServer';

value = registry_get_sz(key:key, item:item, type:type);
default = script_get_preference('Value');

if(value == ''){
  value = 'None';
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