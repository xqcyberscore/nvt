###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vlc_media_player_mult_vuln_jul13_win.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# VLC Media Player Multiple Vulnerabilities - July 13 (Windows)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803900");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2013-1868", "CVE-2012-5855");
  script_bugtraq_id(57079,56405);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-07-16 14:24:20 +0530 (Tue, 16 Jul 2013)");
  script_name("VLC Media Player Multiple Vulnerabilities - July 13 (Windows)");

  tag_summary = "This host is installed with VLC Media Player and is prone to multiple
vulnerabilities.";

  tag_insight = "Multiple flaws due to,

 - Error in 'SHAddToRecentDocs()' function.

 - Error due to improper validation of user supplied inputs when handling
   HTML subtitle files.";

  tag_vuldetect = "Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_impact = "Successful exploitation will allow attackers to overflow buffer, cause denial
of service or potentially execution of arbitrary code.

  Impact Level: System/Application";

  tag_affected = "VLC media player version 2.0.4 and prior on Windows";

  tag_solution = "Upgrade to VLC media player version 2.0.5 or later,
For updates refer to http://www.videolan.org/vlc";

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://www.videolan.org/news.html");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/79823");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_vlc_media_player_detect_win.nasl");
  script_mandatory_keys("VLCPlayer/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE );
vers = infos['version'];
path = infos['location'];

## Check for VLC Media Player Version <= 2.0.4
if( version_is_less_equal( version:vers, test_version:"2.0.4" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.0.5", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );