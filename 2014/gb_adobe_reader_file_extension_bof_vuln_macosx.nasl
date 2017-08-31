###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_reader_file_extension_bof_vuln_macosx.nasl 6759 2017-07-19 09:56:33Z teissa $
#
# Adobe Reader 'File Extension' Buffer Overflow Vulnerability (Mac OS X)
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804261";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6759 $");
  script_cve_id("CVE-2004-0632");
  script_bugtraq_id(10696);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-07-19 11:56:33 +0200 (Wed, 19 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-04-16 10:39:15 +0530 (Wed, 16 Apr 2014)");
  script_name("Adobe Reader 'File Extension' Buffer Overflow Vulnerability (Mac OS X)");

  tag_summary =
"This host is installed with Adobe Reader and is prone to buffer overflow
vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Flaw exist due to a parsing and boundary error when splitting filename paths
into components.";

  tag_impact =
"Successful exploitation will allow attacker to conduct denial of service and
possibly execute arbitrary code.

Impact Level: System/Application";

  tag_affected =
"Adobe Reader version 6.0 and 6.0.1 on Mac OS X.";

  tag_solution =
"Upgrade to Adobe Reader 6.0.2 or later. For
updates refer to http://get.adobe.com/reader";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/12053");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/16667");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/techdocs/330527.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Reader/MacOSX/Version");
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

if(readerVer && readerVer =~ "^6")
{
  ## Check Adobe Reader version
  if(version_in_range(version:readerVer, test_version:"6.0", test_version2:"6.0.1"))
  {
    security_message(0);
    exit(0);
  }
}
