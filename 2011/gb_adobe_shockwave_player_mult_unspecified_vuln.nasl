###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_shockwave_player_mult_unspecified_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Adobe Shockwave Player Multiple Unspecified Vulnerabilities
#
# Authors:
# N Shashi Kiran <nskiran@secpod.com>
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

tag_impact = "Successful attack could allow attackers to execute of arbitrary code or
  cause a denial of service.
  Impact Level: Application";
tag_affected = "Adobe Shockwave Player version before 11.6.0.626 on Windows.";
tag_insight = "The flaws are due to unspecified vectors. For more details please refer
  reference section.";
tag_solution = "Upgrade to Adobe Flash Player version 11.6.0.626 or later.
  For updates refer to http://get.adobe.com/shockwave";
tag_summary = "This host has Adobe Shockwave Player installed and is prone to
  multiple unspecified vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802301");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-06-21 13:52:36 +0200 (Tue, 21 Jun 2011)");
  script_cve_id("CVE-2011-0317", "CVE-2011-0318", "CVE-2011-0319", "CVE-2011-0320",
                "CVE-2011-0335", "CVE-2011-2108", "CVE-2011-2109", "CVE-2011-2111",
                "CVE-2011-2112", "CVE-2011-2113", "CVE-2011-2114", "CVE-2011-2115",
                "CVE-2011-2118", "CVE-2011-2119", "CVE-2011-2120", "CVE-2011-2121",
                "CVE-2011-2122", "CVE-2011-2123", "CVE-2011-2124", "CVE-2011-2125",
                "CVE-2011-2126", "CVE-2011-2127", "CVE-2011-2128");
  script_bugtraq_id(48284, 48286, 48287, 48288, 48275, 48311, 48273, 48300,
                    48278, 48306, 48298, 48299, 48304, 48296, 48307, 48302,
                    48297, 48310, 48294, 48308, 48309, 48289, 48290);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Adobe Shockwave Player Multiple Unspecified Vulnerabilities");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb11-17.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_shockwave_player_detect.nasl");
  script_require_keys("Adobe/ShockwavePlayer/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

shockVer = get_kb_item("Adobe/ShockwavePlayer/Ver");
if(!shockVer){
  exit(0);
}

# Grep for versions prior to 11.6.0.626
if(version_is_less(version:shockVer, test_version:"11.6.0.626")){
  security_message(0);
}
