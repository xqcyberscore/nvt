###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_win_media_player_dos_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Windows Media Player Denial Of Service Vulnerability
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

tag_impact = "Successful exploitation will allow attackers to cause denial of
service.

Impact Level: Application";

tag_affected = "Windows Media Player version 11.0.5721.5262";

tag_insight = "The flaw is caused to unspecified error in the application.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with Windows Media Player and is prone to
denial of service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902781");
  script_version("$Revision: 9351 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"creation_date", value:"2011-12-27 18:30:35 +0530 (Tue, 27 Dec 2011)");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_name("Windows Media Player Denial Of Service Vulnerability");


  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_ms_win_media_player_detect_900173.nasl");
  script_require_keys("Win/MediaPlayer/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/108152/wmp11-dos.txt");
  exit(0);
}


include("version_func.inc");

## Get the version
wmpVer = get_kb_item("Win/MediaPlayer/Ver");
if(!wmpVer){
  exit(0);
}

## Check for Windows Media Player version 11.0.5721.5262
if(version_is_equal(version:wmpVer, test_version:"11.0.5721.5262")){
  security_message(0);
}
