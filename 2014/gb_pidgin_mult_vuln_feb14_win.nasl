###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pidgin_mult_vuln_feb14_win.nasl 6769 2017-07-20 09:56:33Z teissa $
#
# Pidgin Multiple Vulnerabilities Feb 2014 (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:pidgin:pidgin";
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804314";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6769 $");
  script_cve_id("CVE-2012-6152", "CVE-2013-6477", "CVE-2013-6478", "CVE-2013-6479",
                "CVE-2013-6481", "CVE-2013-6482", "CVE-2013-6483", "CVE-2013-6484",
                "CVE-2013-6485", "CVE-2013-6486", "CVE-2013-6487", "CVE-2013-6489",
                "CVE-2013-6490", "CVE-2014-0020");
  script_bugtraq_id(65492, 65243, 65189, 65188, 65192, 65195);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-07-20 11:56:33 +0200 (Thu, 20 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-02-14 16:39:04 +0530 (Fri, 14 Feb 2014)");
  script_name("Pidgin Multiple Vulnerabilities Feb 2014 (Windows)");

  tag_summary =
"The host is installed with Pidgin and is prone to multiple vulnerabilities.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"The flaws are due to an,
- Improper validation of data by the Yahoo protocol plugin.
- Improper validation of argument counts by IRC protocol plugin.
- Improper validation of input to content-length header.
- Integer signedness error in the 'MXit' functionality.
- Integer overflow in 'ibpurple/protocols/gg/lib/http.c' in the 'Gadu-Gadu'
(gg) parser.
- Error due to incomplete fix for earlier flaw.
- Integer overflow condition in the 'process_chunked_data' function in 'util.c'.
- Error in 'STUN' protocol implementation in 'libpurple'.
- Error in the 'XMPP' protocol plugin in 'libpurple'.
- Error in the MSN module.
- Improper validation of the length field in 'libpurple/protocols/yahoo/libymsg.c'.
- Improper allocation of memory by 'util.c' in 'libpurple'.
- Error in the libx11 library.
- Multiple integer signedness errors in libpurple.
";

  tag_impact =
"Successful exploitation will allow remote attackers to conduct denial of
service or execute arbitrary programs or spoof iq traffic.

Impact Level: System/Application";

  tag_affected =
"Pidgin version before 2.10.8.";

  tag_solution =
"Upgrade to Pidgin version 2.10.8 or later,
For updates refer to http://www.pidgin.im/";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/56693/");
  script_xref(name : "URL" , value : "http://www.pidgin.im/news/security/?id=70");
  script_xref(name : "URL" , value : "http://www.pidgin.im/news/security/?id=85");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_pidgin_detect_win.nasl");
  script_mandatory_keys("Pidgin/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

## Variable Initialization
pidVer = "";

## Get version
if(!pidVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Grep for vulnerable version
if(version_is_less(version:pidVer, test_version:"2.10.8"))
{
  security_message(0);
  exit(0);
}
