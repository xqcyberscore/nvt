###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_prdts_sec_bypass_vuln_win.nasl 8210 2017-12-21 10:26:31Z cfischer $
#
# Adobe Reader/Acrobat Security Bypass Vulnerability (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (C) 2011 SecPod, http://www.secpod.com
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902387");
  script_version("$Revision: 8210 $");
  script_cve_id("CVE-2011-2102");
  script_bugtraq_id(48253);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-12-21 11:26:31 +0100 (Thu, 21 Dec 2017) $");
  script_tag(name:"creation_date", value:"2011-07-01 16:09:45 +0200 (Fri, 01 Jul 2011)");
  script_name("Adobe Reader/Acrobat Security Bypass Vulnerability (Windows)");

  tag_summary = "This host has Adobe Reader/Acrobat installed, and is/are prone to security
bypass vulnerability.";

  tag_vuldetect = "Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight = "The flaw is caused by an unknown vectors,allows attackers to bypass intended
access restriction.";

  tag_impact = "Successful exploitation allows attackers to bypass intended security
restrictions, which may leads to the other attacks.

Impact Level: System/Application";

  tag_affected = "Adobe Reader version 10.0.1 and prior.

Adobe Acrobat version 10.0.1 and prior.";

  tag_solution = "Upgrade to Adobe Acrobat and Reader version 10.1 or later. For updates refer to
http://www.adobe.com/support/downloads/product.jsp?product=10&platform=Windows";

  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb11-16.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Air_or_Flash_or_Reader_or_Acrobat/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

CPE = "cpe:/a:adobe:acrobat_reader";
if(readerVer = get_app_version(cpe:CPE, nofork:TRUE))
{
  ## Check for Adobe Reader versions
  if(readerVer =~ "10\.")
  {
    if(version_is_less(version:readerVer, test_version:"10.1")) {
      security_message(0);
    }
  }

  if(readerVer =~ "9\.")
  {
    if(version_is_less(version:readerVer, test_version:"9.4.5")) {
      security_message(0);
    }
  }

  if(readerVer =~ "8\.")
  {
    if(version_is_less(version:readerVer, test_version:"8.3")){
      security_message(0);
    }
  }
}

CPE = "cpe:/a:adobe:acrobat";
if(acrobatVer = get_app_version(cpe:CPE))
{

  if(acrobatVer =~ "10\.") {
    if(version_is_less(version:acrobatVer, test_version:"10.1")) {
      security_message(0);
      exit(0);
    }
  }

  if(acrobatVer =~ "9\.") {
    if(version_is_less(version:acrobatVer, test_version:"9.4.5")) {
      security_message(0);
      exit(0);
    }
  }

  if(acrobatVer =~ "8\.") {
    if(version_is_less(version:acrobatVer, test_version:"8.3")) {
      security_message(0);
      exit(0);
    }
  }

}
