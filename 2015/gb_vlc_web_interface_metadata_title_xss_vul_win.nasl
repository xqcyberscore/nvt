###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vlc_web_interface_metadata_title_xss_vul_win.nasl 8174 2017-12-19 12:23:25Z cfischer $
#
# VLC Media Player Web Interface Cross Site Scripting Vulnerability Dec15 (Windows)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.806752");
  script_version("$Revision: 8174 $");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-12-19 13:23:25 +0100 (Tue, 19 Dec 2017) $");
  script_tag(name:"creation_date", value:"2015-12-01 10:33:43 +0530 (Tue, 01 Dec 2015)");
  script_tag(name:"qod_type", value:"registry");
  script_name("VLC Media Player Web Interface Cross Site Scripting Vulnerability Dec15 (Windows)");

  script_tag(name: "summary" , value:"The host is installed with VLC media player
  and is prone to cross site scripting vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw is due to insufficient
  sanitization of metadata that is getting executed.");

  script_tag(name: "impact" , value:"Successful exploitation will allow remote
  attackers to execute arbitrary script code in a user's browser session within
  the trust relationship between their browser and the serve.

  Impact Level: Application");

  script_tag(name: "affected" , value:"VideoLAN VLC media player 2.2.1 on Windows.");

  script_tag(name: "solution" , value:"Upgrade to VideoLAN VLC media player version
  2.2.2 or later. 
  For updates refer to http://www.videolan.org");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "https://www.exploit-db.com/exploits/38706");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("General");
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
if(version_is_equal(version:vlcVer, test_version:"2.2.1"))
{
  report = 'Installed version: ' + vlcVer + '\n' +
           'Fixed version:     2.2.2';
  security_message(data:report);
  exit(0);
}
