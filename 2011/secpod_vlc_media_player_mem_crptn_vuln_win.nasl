###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_vlc_media_player_mem_crptn_vuln_win.nasl 8174 2017-12-19 12:23:25Z cfischer $
#
# VLC Media Player AMV and NSV Data Processing Memory Corruption vulnerability (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod http://www.secpod.com
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

tag_impact = "Successful exploitation could allow attackers to execute arbitrary code by
  tricking a user into opening a malicious file or visiting a specially crafted
  web page.
  Impact Level: Application";
tag_affected = "VLC media player version prior to 1.1.8 on Windows.";
tag_insight = "The flaw is caused by a memory corruption error in the 'libdirectx' plugin when
  processing malformed NSV or AMV data, which allows the attackers to execute
  arbitrary code.";
tag_solution = "Upgrade to the VLC media player version 1.1.8 or later,
  For updates refer to http://www.videolan.org/vlc/";
tag_summary = "The host is installed with VLC Media Player and is prone to memory
  corruption vulnerability.";

if(description)
{
  script_id(902406);
  script_version("$Revision: 8174 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-19 13:23:25 +0100 (Tue, 19 Dec 2017) $");
  script_tag(name:"creation_date", value:"2011-04-01 15:39:52 +0200 (Fri, 01 Apr 2011)");
  script_cve_id("CVE-2010-3275", "CVE-2010-3276");
  script_bugtraq_id(47012);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("VLC Media Player AMV and NSV Data Processing Memory Corruption vulnerability (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/43826");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1025250");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/66259");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/0759");

  script_copyright("Copyright (c) 2011 SecPod");
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

## Check for VLC Media Player Version less than 1.1.8
if( version_is_less( version:vers, test_version:"1.1.8" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.1.8", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );