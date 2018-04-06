#############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_acrobat_mult_unspecified_vuln01_feb13_macosx.nasl 27950 2013-02-19 19:32:21Z feb$
#
# Adobe Acrobat Multiple Unspecified Vulnerabilities -01 Feb13 (Mac OS X)
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

tag_impact = "Successful exploitation will allow attacker to execute arbitrary
code or cause a denial of service via a crafted PDF document.

Impact level: System/Application";

tag_affected = "Adobe Acrobat Version 9.x prior to 9.5.4 on Mac OS X
Adobe Acrobat X Version 10.x prior to 10.1.6 on Mac OS X
Adobe Acrobat XI Version 11.x prior to 11.0.02 on Mac OS X";

tag_insight = "The flaws are due to unspecified errors.";

tag_solution = "Upgrade to version 9.5.4 or X (10.1.6) or XI (11.0.02) or later,
For updates refer to http://www.adobe.com";

tag_summary = "This host is installed with Adobe Acrobat and is prone to
multiple unspecified vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803419");
  script_version("$Revision: 9353 $");
  script_bugtraq_id(57931, 57947);
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-02-19 19:32:21 +0530 (Tue, 19 Feb 2013)");
  script_cve_id("CVE-2013-0640", "CVE-2013-0641");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Adobe Acrobat Multiple Unspecified Vulnerabilities -01 Feb13 (Mac OS X)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/52196");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/advisories/apsa13-02.html");
  script_xref(name : "URL" , value : "http://blogs.adobe.com/psirt/2013/02/adobe-reader-and-acrobat-vulnerability-report.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl", "ssh_authorization_init.nasl");
  script_mandatory_keys("Adobe/Acrobat/MacOSX/Version");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

## Variable Initialization
acrobatVer = "";

acrobatVer = get_kb_item("Adobe/Acrobat/MacOSX/Version");

if(acrobatVer && acrobatVer =~ "^9|10|11")
{
  # Check Adobe Acrobat version is 9.x <= 9.5.3, 10.x <= 10.1.5 and 11.x <= 11.0.01
  if((version_in_range(version:acrobatVer, test_version:"9.0", test_version2: "9.5.3"))||
     (version_in_range(version:acrobatVer, test_version:"10.0", test_version2: "10.1.5"))||
     (version_in_range(version:acrobatVer, test_version:"11.0", test_version2: "11.0.01")))
  {
    security_message(0);
    exit(0);
  }
}
