#############################################################################
# OpenVAS Vulnerability Test
#
# Hamster Audio Player Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.800692");
  script_version("2019-10-07T09:19:02+0000");
  script_tag(name:"last_modification", value:"2019-10-07 09:19:02 +0000 (Mon, 07 Oct 2019)");
  script_tag(name:"creation_date", value:"2009-07-23 21:05:26 +0200 (Thu, 23 Jul 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Hamster Audio Player Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"Detection of the Hamster Audio Player.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

if(!get_kb_item("SMB/WindowsVersion"))
  exit(0);

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key))
  exit(0);

foreach item(registry_enum_keys(key:key)) {

  appName = registry_get_sz(key:key + item, item:"DisplayName");
  if(!appName || "Hamster" >!< appName || appName !~ "Hamster [0-9.]+") #nb: Both checks are used because !~ is case insensitive...
    continue;

  concluded  = "Registry-Key:   " + key + item + '\n';
  concluded += "DisplayName:    " + appName;
  location = "unknown";
  version = "unknown";

  vers = eregmatch(pattern:"Hamster ([0-9.]+([a-z]+)?)", string:appName);
  if(!isnull(vers[1]))
    version = vers[1];

  set_kb_item(name:"hamster/audio-player/detected", value:TRUE);

  register_and_report_cpe(app:"Hamster Audio Player", ver:version, concluded:concluded,
                          base:"cpe:/a:ondanera.net:hamster_audio_player:", expr:"^([0-9.]+([a-z0-9]+)?)", insloc:location, regService:"smb-login", regPort:0);
  exit(0);
}

exit(0);
