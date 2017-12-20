###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vlc_media_player_dos_vuln_mar14_win.nasl 8174 2017-12-19 12:23:25Z cfischer $
#
# VLC Media Player Denial of Service Vulnerability Mar14 (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804346";
CPE = "cpe:/a:videolan:vlc_media_player";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 8174 $");
  script_cve_id("CVE-2013-7340");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-12-19 13:23:25 +0100 (Tue, 19 Dec 2017) $");
  script_tag(name:"creation_date", value:"2014-03-25 13:19:16 +0530 (Tue, 25 Mar 2014)");
  script_name("VLC Media Player Denial of Service Vulnerability Mar14 (Windows)");

  tag_summary =
"This host is installed with VLC Media Player and is prone to denial of
service vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"The flaw exists due to some unspecified error.";

  tag_impact =
"Successful exploitation will allow attackers to cause a denial of service
conditions.

Impact Level: Application";

 tag_affected =
"VLC media player version 2.0.6 and prior on Windows.";

  tag_solution =
"Upgrade to VLC media player version 2.0.7 or later,
For updates refer to http://www.videolan.org/vlc";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://www.videolan.org/developers/vlc-branch/NEWS");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("secpod_vlc_media_player_detect_win.nasl");
  script_mandatory_keys("VLCPlayer/Win/Installed");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

## Variable Initialization
vlcVer = "";

## Get the VLC version
vlcVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID);
if(!vlcVer){
  exit(0);
}

## Check for VLC Media Player Version < 2.0.7
if(version_is_less(version:vlcVer, test_version:"2.0.7"))
{
  security_message(0);
  exit(0);
}
