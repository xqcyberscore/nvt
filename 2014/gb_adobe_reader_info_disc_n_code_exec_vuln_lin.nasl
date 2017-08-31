###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_reader_info_disc_n_code_exec_vuln_lin.nasl 6637 2017-07-10 09:58:13Z teissa $
#
# Adobe Reader Information Disclosure & Code Execution Vulnerabilities (Linux)
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804399";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6637 $");
  script_cve_id("CVE-2005-1841", "CVE-2005-1625");
  script_bugtraq_id(14153, 14165);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 11:58:13 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-04-15 13:50:57 +0530 (Tue, 15 Apr 2014)");
  script_name("Adobe Reader Information Disclosure & Code Execution Vulnerabilities (Linux)");

  tag_summary =
"This host is installed with Adobe Reader and is prone to information disclosure
and remote code execution vulnerabilities.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Flaws exist due to,
- A boundary error in 'UnixAppOpenFilePerform' function while opening a document
containing a '/Filespec' tag.
- Temporary files being created with permissions based on the user's umask in
the '/tmp' folder.";

  tag_impact =
"Successful exploitation will allow attackers to conduct arbitrary code
execution and gain knowledge of sensitive information.

Impact Level: System/Application";

  tag_affected =
"Adobe Reader version 5.0.9 and 5.0.10 on Linux.";

  tag_solution =
"Upgrade to Adobe Reader version 7.0 or later. For
updates refer to http://get.adobe.com/reader";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/15934");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/14457");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/techdocs/329121.html");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/techdocs/329083.html");
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

if(readerVer && readerVer =~ "^5")
{
  ## Check Adobe Reader version
  if(version_in_range(version:readerVer, test_version:"5.0.9", test_version2:"5.0.10"))
  {
    security_message(0);
    exit(0);
  }
}
