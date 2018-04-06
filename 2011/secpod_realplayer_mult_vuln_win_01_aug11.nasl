###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_realplayer_mult_vuln_win_01_aug11.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# RealNetworks RealPlayer Multiple Vulnerabilities (Windows) - Aug11
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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

tag_impact = "Successful exploitation allows remote attackers to execute arbitrary
  code or cause a denial of service.
  Impact Level: System/Application";
tag_affected = "RealPlayer versions 11.0 through 11.1
  RealPlayer SP versions 1.0 through 1.1.5 (12.x)
  RealPlayer versions 14.0.0 through 14.0.5";
tag_insight = "Multiple flaws are due to,
  - A cross-zone scripting error in the ActiveX which allows remote attackers
    to inject arbitrary web script in the Local Zone via a local HTML document.
  - A buffer overflow error which allows remote attackers to execute arbitrary
    code via a crafted raw_data_frame field in an AAC file and a crafted QCP
    file.
  - An use-after-free error in the AutoUpdate feature which allows remote
    attackers to execute arbitrary code via unspecified vectors.";
tag_solution = "Upgrade to RealPlayer version 14.0.6 or later,
  For updates refer to http://www.real.com/player";
tag_summary = "This host is installed with RealPlayer which is prone to multiple
  vulnerabilities";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902621");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-08-31 10:37:30 +0200 (Wed, 31 Aug 2011)");
  script_cve_id("CVE-2011-2945", "CVE-2011-2947", "CVE-2011-2950", "CVE-2011-2951",
                "CVE-2011-2954");
  script_bugtraq_id(49196, 49178, 49172, 49173, 49199);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("RealNetworks RealPlayer Multiple Vulnerabilities (Windows) - Aug11");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/44014/");
  script_xref(name : "URL" , value : "http://service.real.com/realplayer/security/08162011_player/en/");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("General");
  script_dependencies("gb_realplayer_detect_win.nasl");
  script_require_keys("RealPlayer/Win/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
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
   version_in_range(version:rpVer, test_version:"12.0.1", test_version2:"12.0.1.660")){
  security_message(0);
}
