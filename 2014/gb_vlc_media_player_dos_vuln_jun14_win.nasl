###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vlc_media_player_dos_vuln_jun14_win.nasl 8174 2017-12-19 12:23:25Z cfischer $
#
# VLC Media Player Denial of Service Vulnerability -01 June14 (Windows)
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

CPE = "cpe:/a:videolan:vlc_media_player";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804613");
  script_version("$Revision: 8174 $");
  script_cve_id("CVE-2014-3441");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-12-19 13:23:25 +0100 (Tue, 19 Dec 2017) $");
  script_tag(name:"creation_date", value:"2014-06-04 11:00:40 +0530 (Wed, 04 Jun 2014)");
  script_name("VLC Media Player Denial of Service Vulnerability -01 June14 (Windows)");

  tag_summary =
"This host is installed with VLC Media Player and is prone to denial of
service vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"The flaw exists as user-supplied input is not properly sanitized when handling
a specially crafted WAV file.";

  tag_impact =
"Successful exploitation will allow attackers to cause a denial of service
conditions or potentially execute arbitrary code.

Impact Level: System/Application";

 tag_affected =
"VLC media player version 2.1.3 on Windows.";

  tag_solution =
"No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/126564");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
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
vlcVer = get_app_version(cpe:CPE);
if(!vlcVer){
  exit(0);
}

## Check for VLC Media Player version = 2.1.3
if(version_is_equal(version:vlcVer, test_version:"2.1.3"))
{
  security_message(0);
  exit(0);
}
