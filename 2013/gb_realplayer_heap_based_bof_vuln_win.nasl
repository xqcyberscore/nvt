###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_realplayer_heap_based_bof_vuln_win.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# RealNetworks RealPlayer Heap Based BoF Vulnerability (Windows)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation allows remote attackers to to cause heap
  based buffer overflow leading to arbitrary code execution or denial of
  service condition.
  Impact Level: System/Application";

tag_affected = "RealPlayer version 16.0.0.0 and prior";
tag_insight = "Flaw due to improper sanitization of user-supplied input when parsing MP4
  files.";
tag_solution = "Upgrade to RealPlayer version 16.0.1.18 or later,
  For updates refer to http://www.real.com/player";
tag_summary = "This host is installed with RealPlayer which is prone to heap
  based buffer overflow vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803601");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2013-1750");
  script_bugtraq_id(58539);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-05-14 18:27:30 +0530 (Tue, 14 May 2013)");
  script_name("RealNetworks RealPlayer Heap Based BoF Vulnerability (Windows)");
  script_xref(name : "URL" , value : "http://www.scip.ch/en/?vuldb.8026");
  script_xref(name : "URL" , value : "http://cxsecurity.com/cveshow/CVE-2013-1750");
  script_xref(name : "URL" , value : "http://service.real.com/realplayer/security/03152013_player/en");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_realplayer_detect_win.nasl");
  script_mandatory_keys("RealPlayer/Win/Ver");
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
rpVer = "";

## Get RealPlayer version from KB
rpVer = get_kb_item("RealPlayer/Win/Ver");
if(!rpVer){
  exit(0);
}

## Check for Realplayer version <= 16.0.0.0
if(version_is_less_equal(version:rpVer, test_version:"16.0.0.0"))
{
  security_message(0);
  exit(0);
}
