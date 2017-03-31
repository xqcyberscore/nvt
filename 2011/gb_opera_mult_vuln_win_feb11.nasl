###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opera_mult_vuln_win_feb11.nasl 4590 2016-11-22 08:45:15Z cfi $
#
# Opera Browser Multiple Vulnerabilities Feb-11 (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary code
  and cause a denial of service.
  Impact Level: Application";
tag_affected = "Opera Web Browser Version prior 11.01";
tag_insight = "Multiple flaws are cause due to:
  - An error in determining the pathname of the filesystem-viewing application
  - An error in handling large form inputs
  - An error Cascading Style Sheets (CSS) Extensions for XML implementation
  - An error while restricting the use of opera: URLs
  - An error in handling of redirections and unspecified other HTTP responses
  - An error in implementing the 'Clear all email account passwords' option,
    which might allow physically proximate attackers to access an e-mail
    account via an unattended workstation
  - An error in the implementation of Wireless Application Protocol (WAP)
    dropdown lists.";
tag_solution = "Upgrade to Opera Web Browser Version 11.01 or later,
  For updates refer to http://www.opera.com/download/";
tag_summary = "The host is installed with Opera browser and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(801728);
  script_version("$Revision: 4590 $");
  script_tag(name:"last_modification", value:"$Date: 2016-11-22 09:45:15 +0100 (Tue, 22 Nov 2016) $");
  script_tag(name:"creation_date", value:"2011-02-07 15:21:16 +0100 (Mon, 07 Feb 2011)");
  script_cve_id("CVE-2011-0450", "CVE-2011-0682", "CVE-2011-0681", "CVE-2011-0683",
                "CVE-2011-0684", "CVE-2011-0685", "CVE-2011-0687", "CVE-2011-0686");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Opera Browser Multiple Vulnerabilities Feb-11 (Windows)");
  script_xref(name : "URL" , value : "http://www.opera.com/support/kb/view/985/");
  script_xref(name : "URL" , value : "http://www.opera.com/docs/changelogs/windows/1101/");

  script_tag(name:"qod_type", value:"registry");
  script_summary("Check for the version of Opera");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_opera_detection_win_900036.nasl");
  script_require_keys("Opera/Win/Version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

## Get Opera Version from KB
operaVer = get_kb_item("Opera/Win/Version");

if(operaVer)
{
  ## Grep for Opera Versions prior to 11.01
  if(version_is_less(version:operaVer, test_version:"11.01")){
    security_message(0);
  }
}
