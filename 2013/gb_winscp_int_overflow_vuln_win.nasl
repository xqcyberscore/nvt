###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_winscp_int_overflow_vuln_win.nasl 6086 2017-05-09 09:03:30Z teissa $
#
# WinSCP Integer Overflow Vulnerability (Windows)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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

tag_impact = "
  Impact Level: System/Application";

CPE = "cpe:/a:winscp:winscp";
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803873";

if (description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6086 $");
  script_cve_id("CVE-2013-4852");
  script_bugtraq_id(61599);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-05-09 11:03:30 +0200 (Tue, 09 May 2017) $");
  script_tag(name:"creation_date", value:"2013-08-21 13:50:22 +0530 (Wed, 21 Aug 2013)");
  script_name("WinSCP Integer Overflow Vulnerability (Windows)");

  tag_summary =
"The host is installed with WinSCP and is prone to integer overflow
vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Flaw is due to improper validation of message lengths in the getstring()
function in sshrsa.c and sshdss.c when handling negative SSH handshake.";

  tag_impact =
"Successful exploitation will allow attackers to cause heap-based buffer
overflows, resulting in a denial of service or potentially allowing the
execution of arbitrary code.";

  tag_affected =
"WinSCP version before 5.1.6 on Windows";

  tag_solution =
"Upgrade to version 5.1.6 or later,
For updates refer to http://winscp.net";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/54355");
  script_xref(name : "URL" , value : "http://winscp.net/eng/docs/history#5.1.6");
  script_xref(name : "URL" , value : "http://winscp.net/tracker/show_bug.cgi?id=1017");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_winscp_detect_win.nasl");
  script_mandatory_keys("WinSCP/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Confirm Windows
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Get the version
if(!scpVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Check for WinSCP version
if(version_is_less(version:scpVer, test_version:"5.1.6"))
{
  security_message(0);
  exit(0);
}
