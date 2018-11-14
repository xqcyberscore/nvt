##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_serverscheck_monitoring_detect_win.nasl 12334 2018-11-13 11:57:29Z mmartin $
#
# ServersCheck Monitoring Software Version Detection (Windows)
#
# Authors:
# Michael Martin <michael.martin@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH, http//www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.107365");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 12334 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-13 12:57:29 +0100 (Tue, 13 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-11-10 14:45:11 +0100 (Sat, 10 Nov 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("ServersCheck Monitoring Software Version Detection (Windows)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"summary", value:"This script detects the installed version
  of ServersCheck Monitoring Software for Windows.");
  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("secpod_smb_func.inc");

foreach key(make_list_unique("",
  registry_enum_keys(key:"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"))){

  key = "SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\" + key;
  if(!registry_key_exists(key:key)) continue;

  appName = registry_get_sz(key:key, item:"DisplayName");
  if(appName !~ "ServersCheck Monitoring Software") continue;
  Loc = registry_get_sz(key:key, item:"InstallLocation");
  Ver = eregmatch( string:appName, pattern:"([0-9]+\.[0-9]+\.[0-9])$" );
  vers = Ver[1];
  Concluded = appName;
  set_kb_item(name:"ServersCheck/Monitoring_Software/Win/detected", value:TRUE);
  set_kb_item( name: "ServersCheck/Monitoring_Software_or_Server/detected", value: TRUE );
  set_kb_item(name:"ServersCheck/Monitoring_Software/Win/Ver", value:Ver);

  register_and_report_cpe(app:"ServersCheck Monitoring Software" , ver:vers, concluded: appName,
    base:"cpe:/a:serverscheck:monitoring_software:", expr:"^([0-9.]+)", insloc:Loc);
  exit(0);
}
exit(0);
