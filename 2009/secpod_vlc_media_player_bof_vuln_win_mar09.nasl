###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_vlc_media_player_bof_vuln_win_mar09.nasl 8174 2017-12-19 12:23:25Z cfischer $
#
# VLC Media Player Stack Overflow Vulnerability (Win-Mar09)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:videolan:vlc_media_player";

tag_impact = "Successful exploitation allows the attacker to execute arbitrary codes
  with escalated privileges and cause overflow in stack.
  Impact Level: Application";
tag_affected = "VLC media player 0.9.8a and prior on Windows.";
tag_insight = "This flaw is due to improper boundary checking in status.xml in the web
  interface by an overly long request.";
tag_solution = "Upgrade to VLC media player version 1.0 or later,
  For updates refer to http://www.videolan.org/vlc";
tag_summary = "This host is installed with VLC Media Player and is prone to
  Stack Overflow Vulnerability.";

if(description)
{
  script_id(900530);
  script_version("$Revision: 8174 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-19 13:23:25 +0100 (Tue, 19 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-03-26 11:19:12 +0100 (Thu, 26 Mar 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-1045");
  script_bugtraq_id(34126);
  script_name("VLC Media Player Stack Overflow Vulnerability (Win-Mar09)");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8213");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/49249");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2009/03/17/4");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_vlc_media_player_detect_win.nasl");
  script_mandatory_keys("VLCPlayer/Win/Installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE );
vers = infos['version'];
path = infos['location'];

if( version_is_less_equal( version:vers, test_version:"0.9.8a" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.0", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );