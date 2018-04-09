###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vlc_media_player_mult_vuln_jan15_lin.nasl 9381 2018-04-06 11:21:01Z cfischer $
#
# VLC Media Player Multiple Vulnerabilities -02 Jan15 (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.805426");
  script_version("$Revision: 9381 $");
  script_cve_id("CVE-2014-9598", "CVE-2014-9597");
  script_bugtraq_id(72106,72105);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 13:21:01 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2015-01-27 17:11:51 +0530 (Tue, 27 Jan 2015)");
  script_name("VLC Media Player Multiple Vulnerabilities -02 Jan15 (Linux)");

  script_tag(name: "summary" , value:"The host is installed with VLC Media
  player and is prone to multiple vulnerabilities.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"Multiple Flaws are due to:
  - Improper input sanitization by 'picture_Release' function in misc/picture.c.
  - Improper input sanitization by 'picture_pool_Delete' function in
    misc/picture_pool.c.");

  script_tag(name: "impact" , value:"Successful exploitation will allow remote
  attackers to execute arbitrary code or cause a denial of service.

  Impact Level: System/Application");

  script_tag(name: "affected" , value:"VideoLAN VLC media player 2.1.5 on
  Linux.");

  script_tag(name: "solution" , value:"Upgrade to VideoLAN VLC media player
  version 2.2.0-rc2 or later.
  For updates refer to http://www.videolan.org/vlc");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2015/Jan/72");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/130004/");

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_vlc_media_player_detect_lin.nasl");
  script_mandatory_keys("VLCPlayer/Lin/Ver");
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

## Grep for vulnerable version
if(version_is_equal(version:vlcVer, test_version:"2.1.5"))
{
  report = 'Installed version: ' + vlcVer + '\n' +
             'Fixed version:     ' + "2.2.0-rc2" + '\n';
  security_message(data:report );
  exit(0);
}
