###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vlc_media_player_dos_vul_april16_win.nasl 8174 2017-12-19 12:23:25Z cfischer $
#
# VLC Media Player Denial of Service Vulnerability April-16 (Windows)
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:videolan:vlc_media_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807929");
  script_version("$Revision: 8174 $");
  script_cve_id("CVE-2016-3941");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-12-19 13:23:25 +0100 (Tue, 19 Dec 2017) $");
  script_tag(name:"creation_date", value:"2016-04-26 11:09:19 +0530 (Tue, 26 Apr 2016)");
  script_tag(name:"qod_type", value:"registry");
  script_name("VLC Media Player Denial of Service Vulnerability April-16 (Windows)");

  script_tag(name: "summary" , value:"The host is installed with VLC media player
  and is prone to denial of service vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw is due to the buffer overflow in
  the 'AStreamPeekStream' function in 'input/stream.c' script.");

  script_tag(name: "impact" , value:"Successful exploitation will allow remote
  attackers to cause a denial of service (crash) and possibly execute arbitrary
  code via crafted wav file.

  Impact Level: System/Application");

  script_tag(name: "affected" , value:"VideoLAN VLC media player before 2.2.0 
  on Windows.");

  script_tag(name: "solution" , value:"Upgrade to VideoLAN VLC media player version
  2.2.0 or later. For details refer to http://www.videolan.org");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1035456");
  script_xref(name : "URL" , value : "https://bugs.launchpad.net/ubuntu/+source/vlc/+bug/1533633");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_vlc_media_player_detect_win.nasl");
  script_mandatory_keys("VLCPlayer/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

## Variable Initialization
vlcVer = "";
report = "";

## Get version
if(!vlcVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Check VLC media player vulnerable version
if(version_is_less(version:vlcVer, test_version:"2.2.0"))
{
  report = report_fixed_ver(installed_version:vlcVer, fixed_version:"2.2.0");
  security_message(data:report);
  exit(0);
}
