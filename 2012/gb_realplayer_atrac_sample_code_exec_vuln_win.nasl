###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_realplayer_atrac_sample_code_exec_vuln_win.nasl 8671 2018-02-05 16:38:48Z teissa $
#
# RealNetworks RealPlayer Atrac Sample Decoding Remote Code Execution Vulnerability (Windows)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation allows remote attackers to execute arbitrary
  code.
  Impact Level: Application";
tag_affected = "RealPlayer versions 11.x and 14.x
  RealPlayer SP versions 1.0 through 1.1.5 (12.0.0.879) on Windows";
tag_insight = "The flaw is due to an improper decoding of samples by ATRAC codec,
  which allows remote attackers to execute arbitrary code via a crafted ATRAC
  audio file.";
tag_solution = "Upgrade to RealPlayer version 15.2.71 or later,
  For updates refer to http://www.real.com/player";
tag_summary = "This host is installed with RealPlayer which is prone to remote
  code execution vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802801");
  script_version("$Revision: 8671 $");
  script_cve_id("CVE-2012-0928");
  script_bugtraq_id(51890);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-02-05 17:38:48 +0100 (Mon, 05 Feb 2018) $");
  script_tag(name:"creation_date", value:"2012-02-21 15:19:43 +0530 (Tue, 21 Feb 2012)");
  script_name(" RealNetworks RealPlayer Atrac Sample Decoding Remote Code Execution Vulnerability (Windows)");
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1026643");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/51890");
  script_xref(name : "URL" , value : "http://service.real.com/realplayer/security/02062012_player/en/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_realplayer_detect_win.nasl");
  script_require_keys("RealPlayer/Win/Ver");
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

# Variable Initialization
rpVer = NULL;

#Get Version
rpVer = get_kb_item("RealPlayer/Win/Ver");
if(isnull(rpVer)){
  exit(0);
}

## Check for Realplayer version
# versions 14 comes has 12.0.1
if((rpVer =~ "^11\.*") || (rpVer =~ "^12\.0\.1\.*") ||
   version_in_range(version:rpVer, test_version:"12.0.0", test_version2:"12.0.0.879")){
  security_message(0);
}
