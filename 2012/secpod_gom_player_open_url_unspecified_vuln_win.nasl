###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_gom_player_open_url_unspecified_vuln_win.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# GOM Media Player 'Open URL' Feature Unspecified Vulnerability (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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

tag_impact = "It has unknown impact and attack vectors.
  Impact Level: Application";
tag_affected = "GOM Media Player version prior to 2.1.39.5101 on Windows";
tag_insight = "The flaw is due to an unspecified error in the Open URL feature.";
tag_solution = "Upgrade to GOM Media Player 2.1.39.5101 or later,
  For updates refer to http://www.gomlab.com/eng/";
tag_summary = "This host is installed with GOM Media Player and is prone to
  unspecified vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903003");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2012-1774");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-03-21 17:12:10 +0530 (Wed, 21 Mar 2012)");
  script_name("GOM Media Player 'Open URL' Feature Unspecified Vulnerability (Windows)");
  script_xref(name : "URL" , value : "http://www.security-database.com/cvss.php?alert=CVE-2012-1774");
  script_xref(name : "URL" , value : "http://olex.openlogic.com/wazi/package/gom_media_player/security-notifications/");
  script_xref(name : "URL" , value : "http://heapoverflow.com/f0rums/advisories/29715-cve-2012-1774-gom_media_player.html");

  script_copyright("Copyright (c) 2012 SecPod");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_gom_player_detect_win.nasl");
  script_require_keys("GOM/Player/Ver/Win");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

## Variable Initialization
gomVer = "";

## Get the version from KB
gomVer = get_kb_item("GOM/Player/Ver/Win");
if(!gomVer){
  exit(0);
}

## Check for GOM Media Player Version less than 2.1.39.5101
if(version_is_less(version:gomVer, test_version:"2.1.39.5101")){
  security_message(0);
}
