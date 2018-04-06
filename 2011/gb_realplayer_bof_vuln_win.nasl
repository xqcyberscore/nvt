###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_realplayer_bof_vuln_win.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# RealNetworks RealPlayer Buffer Overflow Vulnerability (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# - Updated By: Madhuri D <dmadhuri@secpod.com> on 2011-02-25
#     Added CVE-2011-0694 and updated the vulnerability insight.
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

tag_impact = "Successful exploitation allows remote attackers to compromise a
  vulnerable system by convincing a user to open a malicious media file or
  visit a specially crafted web page.";
tag_affected = "RealPlayer versions 11.0 through 11.1
  RealPlayer SP versions 1.0 through 1.1.5 (12.x)
  RealPlayer versions 14.0.0 through 14.0.1";
tag_insight = "The flaws are caused due,
  - a buffer overflow error in the 'vidplin.dll' module when processing
    malformed header data.
  - temporary files that store references to media files having predictable
    names. This can be exploited in combination with the
    'OpenURLInPlayerBrowser()' method of a browser plugin to execute the file.";
tag_solution = "Upgrade to RealPlayer version 14.0.2 or later,
  For updates refer to http://www.real.com/player";
tag_summary = "This host is installed with RealPlayer which is prone to Buffer
  Overflow Vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801749");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-02-18 17:42:11 +0100 (Fri, 18 Feb 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-4393", "CVE-2011-0694");
  script_bugtraq_id(46047);
  script_name("RealNetworks RealPlayer Buffer Overflow Vulnerability (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/43098");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/64960");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/0240");
  script_xref(name : "URL" , value : "http://service.real.com/realplayer/security/01272011_player/en/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Buffer overflow");
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

rpVer = get_kb_item("RealPlayer/Win/Ver");
if(isnull(rpVer)){
  exit(0);
}

## Check for Realplayer version
if(version_in_range(version:rpVer, test_version:"11.0.0", test_version2:"11.0.2.2315") ||
   version_in_range(version:rpVer, test_version:"12.0.0", test_version2:"12.0.0.879") ||
   version_in_range(version:rpVer, test_version:"12.0.1", test_version2:" 12.0.1.632")){
  security_message(0);
}
