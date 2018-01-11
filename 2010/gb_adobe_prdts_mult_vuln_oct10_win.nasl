###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_prdts_mult_vuln_oct10_win.nasl 8338 2018-01-09 08:00:38Z teissa $
#
# Adobe Acrobat and Reader Multiple Vulnerabilities -Oct10 (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will let attackers to crash an affected application or
  execute arbitrary code by tricking a user into opening a specially crafted PDF
  document.

  Impact Level: System/Application";

tag_affected = "Adobe Reader version 8.x before 8.2.5 and 9.x before 9.4,

  Adobe Acrobat version 8.x before 8.2.5  and 9.x before 9.4 on windows.";

tag_insight = "The flaws are caused by memory corruptions, array-indexing, and input validation
  errors when processing malformed data, fonts or images within a PDF document.";

tag_solution = "Upgrade to Adobe Reader/Acrobat version 9.4 or 8.2.5
  For updates refer to http://www.adobe.com";

tag_summary = "This host is installed with Adobe Reader/Acrobat and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801524");
  script_version("$Revision: 8338 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-09 09:00:38 +0100 (Tue, 09 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-10-18 15:37:53 +0200 (Mon, 18 Oct 2010)");
  script_cve_id("CVE-2010-2883", "CVE-2010-2884", "CVE-2010-2888", "CVE-2010-2889",
                "CVE-2010-2890", "CVE-2010-3619", "CVE-2010-3620", "CVE-2010-3621",
                "CVE-2010-3622", "CVE-2010-3625", "CVE-2010-3626", "CVE-2010-3627",
                "CVE-2010-3628", "CVE-2010-3629", "CVE-2010-3630", "CVE-2010-3632",
                "CVE-2010-3656", "CVE-2010-3657", "CVE-2010-3658");
  script_bugtraq_id(43057, 43205, 43739, 43723, 43722, 43724, 43725, 43726, 43729,
                    43730, 43727, 43746, 43734, 43732, 43737, 43735, 43741, 43744,
                    43738);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Adobe Acrobat and Reader Multiple Vulnerabilities -Oct10 (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41435/");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/2573");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb10-21.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Air_or_Flash_or_Reader_or_Acrobat/Win/Installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

CPE = "cpe:/a:adobe:acrobat_reader";
if(readerVer = get_app_version(cpe:CPE, nofork:TRUE))
{
  # Check for Adobe Reader version < 8.2.5 and 9.x to 9.3.4
  if(version_is_less(version:readerVer, test_version:"8.2.5") ||
     version_in_range(version:readerVer, test_version:"9.0", test_version2:"9.3.4"))
  {
    security_message(0);
    exit(0);
  }
}

CPE = "cpe:/a:adobe:acrobat";
if(acrobatVer = get_app_version(cpe:CPE))
{
  # Check for Adobe Acrobat version < 8.2.5 and 9.x to 9.3.4
  if(version_is_less(version:acrobatVer, test_version:"8.2.5") ||
     version_in_range(version:acrobatVer, test_version:"9.0", test_version2:"9.3.4")){
    security_message(0);
  }
}
