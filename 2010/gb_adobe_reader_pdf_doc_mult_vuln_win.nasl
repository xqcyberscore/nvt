###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_reader_pdf_doc_mult_vuln_win.nasl 8210 2017-12-21 10:26:31Z cfischer $
#
# Adobe Reader PDF Handling Multiple Vulnerabilities (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801304");
  script_version("$Revision: 8210 $");
  script_cve_id("CVE-2010-1240", "CVE-2010-1241");
  script_bugtraq_id(39470,39109);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-12-21 11:26:31 +0100 (Thu, 21 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-04-07 16:20:50 +0200 (Wed, 07 Apr 2010)");
  script_name("Adobe Reader PDF Handling Multiple Vulnerabilities (Windows)");

  tag_summary = "This host is installed with Adobe Reader and is prone to multiple
vulnerabilities.";

  tag_vuldetect = "Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight = "The flaws are due to:

- An error in custom heap management system, allows the attackers to execute
arbitrary code via a crafted PDF document.

- An error in  handling of 'Launch File warning dialog' which does not restrict
the contents of one text field allows attackers to execute arbitrary local
program that was specified in a PDF document.";

  tag_impact = "Successful exploitation will allow attacker to execute arbitrary code or cause
a denial of service via a crafted PDF document.

Impact Level: System/Application";

  tag_affected = "Adobe Reader version 9.3.1 on Windows.";

  tag_solution = "Upgrade to Adobe Reader version 9.3.2 or later,
For updates refer to http://www.adobe.com";

  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/16671");
  script_xref(name : "URL" , value : "http://blog.didierstevens.com/2010/03/29/escape-from-pdf/");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb10-17.html");
  script_xref(name : "URL" , value : "http://www.blackhat.com/html/bh-eu-10/bh-eu-10-briefings.html#Li");
  script_xref(name : "URL" , value : "http://lists.immunitysec.com/pipermail/dailydave/2010-April/006075.html");
  script_xref(name : "URL" , value : "http://lists.immunitysec.com/pipermail/dailydave/2010-April/006077.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Reader/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

## Get Reader Version
if(!readerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(readerVer =~ "^9")
{
  # Grep for Adobe Reader version 9.3.1
  if(version_is_equal(version:readerVer, test_version:"9.3.1")){
    security_message(0);
  }
}
