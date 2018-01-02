###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_player_remote_code_exec_vuln_winxp.nasl 8228 2017-12-22 07:29:52Z teissa $
#
# Adobe Flash Player Remote Code Execution Vulnerability (WinXP)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated By:
# Antu Sanadi <santu@secpod.com> on 2010-01-22 #6943
# updated the CVE's and Vulnerability Insight
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:adobe:flash_player";

tag_impact = "Successful exploitation could allow remote attackers to crash an affected
  system or execute arbitrary code by tricking a user into visiting a specially
  crafted web page.
  Impact Level: System.";
tag_affected = "Adobe Flash Player 6.x on Windows XP.";
tag_insight = "The flaw is due to a use-after-free error in the bundled version of Flash
  Player when unloading Flash objects while these are still being accessed using
  script code.";
tag_solution = "Upgrade to Adobe Flash Player 10.0.42.34,
  For updates refer to http://www.adobe.com/downloads/";
tag_summary = "This host has Adobe Flash Player installed and is prone to remote
  code execution vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800420");
  script_version("$Revision: 8228 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-22 08:29:52 +0100 (Fri, 22 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-01-13 15:42:20 +0100 (Wed, 13 Jan 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-0378", "CVE-2010-0379");
  script_name("Adobe Flash Player Remote Code Execution Vulnerability (WinXP)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/27105");
  script_xref(name : "URL" , value : "http://secunia.com/secunia_research/2007-77/");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2010/Jan/1023435.html");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/advisory/979267.mspx");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Win/Installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("host_details.inc");
include("version_func.inc");

if(hotfix_check_sp(xp:4) <= 0){
  exit(0);
}

infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE );
vers = infos['version'];
path = infos['location'];

# Grep for versions 6 Series
if( vers =~ "^6\." ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"10.0.42.34", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );