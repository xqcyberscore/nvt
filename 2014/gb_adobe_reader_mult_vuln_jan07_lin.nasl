###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_reader_mult_vuln_jan07_lin.nasl 6663 2017-07-11 09:58:05Z teissa $
#
# Adobe Reader Multiple Vulnerabilities Jan07 (Linux)
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

CPE = "cpe:/a:adobe:acrobat_reader";
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804394";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6663 $");
  script_cve_id("CVE-2006-5857", "CVE-2007-0046", "CVE-2007-0047", "CVE-2007-0044");
  script_bugtraq_id(21858, 21981);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-07-11 11:58:05 +0200 (Tue, 11 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-04-11 18:00:34 +0530 (Fri, 11 Apr 2014)");
  script_name("Adobe Reader Multiple Vulnerabilities Jan07 (Linux)");

  tag_summary =
"This host is installed with Adobe Reader and is prone to multiple
vulnerabilities.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Flaws exist due to,
- Input passed to a hosted PDF file is not properly sanitised by the browser
plug-in before being returned to users.
- Input passed to a hosted PDF file is not properly handled by the browser
plug-in.";

  tag_impact =
"Successful exploitation will allow attackers to cause memory corruption,
execution of arbitrary code, execution of arbitrary script code in a user's
browser session in context of an affected site and conduct cross site request
forgery attacks.

Impact Level: System/Application";

  tag_affected =
"Adobe Reader version 7.0.8 and prior on Linux.";

  tag_solution =
"Upgrade to Adobe Reader version 7.0.9 or later. For updates refer to
http://get.adobe.com/reader";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/23483");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/31266");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb07-01.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_prdts_detect_lin.nasl");
  script_mandatory_keys("Adobe/Reader/Linux/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
readerVer = "";

## Get version
if(!readerVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

if(readerVer)
{
  ## Check Adobe Reader version <= 7.0.8
  if(version_is_less_equal(version:readerVer, test_version:"7.0.8"))
  {
    security_message(0);
    exit(0);
  }
}
