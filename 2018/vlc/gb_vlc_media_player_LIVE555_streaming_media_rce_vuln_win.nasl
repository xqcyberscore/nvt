###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vlc_media_player_LIVE555_streaming_media_rce_vuln_win.nasl 12203 2018-11-02 14:42:44Z bshakeel $
#
# VLC Media Player LIVE555 RTSP Server code execution vulnerability (Windows)
#
# Authors:
# Vidita V Koushik <vidita@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.814317");
  script_version("$Revision: 12203 $");
  script_cve_id("CVE-2018-4013");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-11-02 15:42:44 +0100 (Fri, 02 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-11-02 13:55:59 +0530 (Fri, 02 Nov 2018)");
  script_name("VLC Media Player LIVE555 RTSP Server code execution vulnerability (Windows)");

  script_tag(name:"summary", value:"The host is installed with VLC Media Player
  and is prone to remote code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists in the function that parses
  HTTP headers for tunneling RTSP over HTTP. An attacker may create a packet
  containing multiple 'Accept:' or 'x-sessioncookie' strings which could cause a
  stack buffer overflow in the function 'lookForHeader'");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to cause a stack-based buffer overflow by sending a specially crafted packet,
  resulting in code execution.");

  script_tag(name:"affected", value:"VLC Media Player versions 3.0.4 and
  before on Windows.");

  script_tag(name:"solution", value:"No known solution is available as of 02nd
  November, 2018. Information regarding this issue will be updated once solution
  details are available. For updates refer to Reference links.");

  script_tag(name:"solution_type", value:"NoneAvailable");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://blog.talosintelligence.com/2018/10/vulnerability-spotlight-live-networks.html");
  script_xref(name:"URL", value:"http://www.live555.com/liveMedia/public/");
  script_xref(name:"URL", value:"https://www.videolan.org/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_vlc_media_player_detect_win.nasl");
  script_mandatory_keys("VLCPlayer/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE );
VLCVer = infos['version'];
VLCpath = infos['location'];

if(version_is_less_equal(version:VLCVer, test_version:"3.0.4"))
{
  report = report_fixed_ver(installed_version:VLCVer, fixed_version:"NoneAvailable", install_path:VLCpath);
  security_message(data: report);
  exit(0);
}
