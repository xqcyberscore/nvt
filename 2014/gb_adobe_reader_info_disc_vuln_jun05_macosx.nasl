###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_reader_info_disc_vuln_jun05_macosx.nasl 6715 2017-07-13 09:57:40Z teissa $
#
# Adobe Reader Information Disclosure Vulnerability Jun05 (Mac OS X)
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804256";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6715 $");
  script_cve_id("CVE-2005-1306", "CVE-2005-1623", "CVE-2005-1624");
  script_bugtraq_id(13962, 14076, 14075);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-07-13 11:57:40 +0200 (Thu, 13 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-04-15 18:00:27 +0530 (Tue, 15 Apr 2014)");
  script_name("Adobe Reader Information Disclosure Vulnerability Jun05 (Mac OS X)");

  tag_summary =
"This host is installed with Adobe Reader and is prone to information
disclosure vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Flaw exist due to an error in the adobe reader control which allows reading
the contents of certain text files.";

  tag_impact =
"Successful exploitation will allow attackers to gain knowledge of potentially
sensitive information and execute arbitrary local programs on user's system.

Impact Level: System/Application";

  tag_affected =
"Adobe Reader version 7.0.0 and 7.0.1 on Mac OS X.";

  tag_solution =
"Upgrade to Adobe Reader 7.0.5 or later. For
updates refer to http://get.adobe.com/reader";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/15698");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1014212");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/techdocs/331710.html");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/techdocs/331709.html");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/techdocs/331711.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
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

if(readerVer && readerVer =~ "^7")
{
  ## Check Adobe Reader version
  if(version_is_equal(version:readerVer, test_version:"7.0.0")||
     version_is_equal(version:readerVer, test_version:"7.0.1"))
  {
    security_message(0);
    exit(0);
  }
}
