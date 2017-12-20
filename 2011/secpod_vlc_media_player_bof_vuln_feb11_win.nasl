###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_vlc_media_player_bof_vuln_feb11_win.nasl 8174 2017-12-19 12:23:25Z cfischer $
#
# VLC Media Player USF and Text Subtitles Decoders BOF Vulnerabilities (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation could allow attackers to crash an affected application
  or execute arbitrary code by convincing a user to open a malicious media file.
  Impact Level: Application";
tag_affected = "VLC media player version 1.x before 1.1.6-rc";
tag_insight = "The flaws are caused by buffer overflow errors in the 'StripTags()' function
  within the USF and Text subtitles decoders 'modules/codec/subtitles/subsdec.c'
  and 'modules/codec/subtitles/subsusf.c' when processing malformed data.";
tag_solution = "Upgrade to the VLC media player version 1.1.6-rc or later,
  For updates refer to http://download.videolan.org/pub/videolan/vlc/";
tag_summary = "The host is installed with VLC Media Player and is prone to buffer
  overflow vulnerabilities.";

if(description)
{
  script_id(902341);
  script_version("$Revision: 8174 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-19 13:23:25 +0100 (Tue, 19 Dec 2017) $");
  script_tag(name:"creation_date", value:"2011-02-23 12:24:37 +0100 (Wed, 23 Feb 2011)");
  script_cve_id("CVE-2011-0522");
  script_bugtraq_id(46008);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("VLC Media Player USF and Text Subtitles Decoders BOF Vulnerabilities (Windows)");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/65029");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/16108/");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/0225");

  script_copyright("Copyright (c) 2011 SecPod");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
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

## Check for VLC Media Player Version less than 1.1.6-rc
if( version_in_range( version:vers, test_version:"1.1", test_version2:"1.1.5" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.1.6-rc", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );