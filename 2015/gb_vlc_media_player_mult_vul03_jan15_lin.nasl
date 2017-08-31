###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vlc_media_player_mult_vul03_jan15_lin.nasl 6513 2017-07-04 09:59:28Z teissa $
#
# VLC Media Player Multiple Vulnerabilities-03 Jan15 (Linux)
#
# Authors:
# Deependra Bapna<bdeependra@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.805314");
  script_version("$Revision: 6513 $");
  script_cve_id("CVE-2010-1445", "CVE-2010-1444", "CVE-2010-1443", "CVE-2010-1442",
                "CVE-2010-1441");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-07-04 11:59:28 +0200 (Tue, 04 Jul 2017) $");
  script_tag(name:"creation_date", value:"2015-01-05 12:37:43 +0530 (Mon, 05 Jan 2015)");
  script_name("VLC Media Player Multiple Vulnerabilities-03 Jan15 (Linux)");

  script_tag(name: "summary" , value:"The host is installed with VLC media player
  and is prone to multiple vulnerabilities.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"Multiple flaws are due to,
  - Multiple errors in the A/52 audio decoder, DTS audio decoder, MPEG audio
  decoder, AVI demuxer, ASF demuxer and Matroska demuxer.
  - An error when processing XSPF playlists.
  - A use-after-free error when attempting to create a playlist of the contents
  of a malformed zip archive.
  - An error in the RTMP implementation.");

  script_tag(name: "impact" , value:"Successful exploitation will allow
  attackers to conduct a denial of service or potentially compromise a
  user's system.

  Impact Level: System/Application");

  script_tag(name: "affected" , value:"VideoLAN VLC media player before 1.0.6
  on Linux.");

  script_tag(name: "solution" , value:"Upgrade to VideoLAN VLC media player
  version 1.0.6 or later. For updates refer http://www.videolan.org/");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/39558");
  script_xref(name : "URL" , value : "http://www.videolan.org/security/sa1003.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_vlc_media_player_detect_lin.nasl");
  script_mandatory_keys("VLCPlayer/Lin/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
vlcVer = "";

## Get version
if(!vlcVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Check VLC media player vulnerable version
if(version_is_less(version:vlcVer, test_version:"1.0.6"))
{
  security_message(0);
  exit(0);
}
