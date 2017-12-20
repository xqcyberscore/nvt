###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vlc_media_player_bof_vuln_jan11_win.nasl 8174 2017-12-19 12:23:25Z cfischer $
#
# VLC Media Player 'CDG decoder' multiple buffer overflow vulnerabilities (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation could allow attackers to crash the affected
  application, or execute arbitrary code by convincing a user to open a
  malicious CD+G (CD+Graphics) media file or visit a specially crafted web
  page.
  Impact Level: Application";
tag_affected = "VLC media player version prior to 1.1.6 on Windows.";
tag_insight = "The flaws are due to an array indexing errors in the 'DecodeTileBlock()'
  and 'DecodeScroll()' [modules/codec/cdg.c] functions within the CDG decoder
  module when processing malformed data.";
tag_solution = "Upgrade to the VLC media player version 1.1.6 or later,
  For updates refer to http://www.videolan.org/vlc/";
tag_summary = "The host is installed with VLC Media Player and is prone multiple
  buffer overflow vulnerabilities.";

if(description)
{
  script_id(801726);
  script_version("$Revision: 8174 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-19 13:23:25 +0100 (Tue, 19 Dec 2017) $");
  script_tag(name:"creation_date", value:"2011-01-31 05:37:34 +0100 (Mon, 31 Jan 2011)");
  script_cve_id("CVE-2011-0021");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("VLC Media Player 'CDG decoder' multiple buffer overflow vulnerabilities (Windows)");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/0185");
  script_xref(name : "URL" , value : "http://openwall.com/lists/oss-security/2011/01/20/3");

  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_vlc_media_player_detect_win.nasl");
  script_mandatory_keys("VLCPlayer/Win/Installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE );
vers = infos['version'];
path = infos['location'];

## Check for VLC Media Player Version less than 1.1.6
if( version_is_less( version:vers, test_version:"1.1.6" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.1.6", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );