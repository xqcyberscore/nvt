###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opera_mult_vuln_oct10_lin.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Opera Browser Multiple Vulnerabilities October-10 (Linux)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  on the target user's system, can obtain sensitive information.
  Impact Level: Application";
tag_affected = "Opera Web Browser version prior 10.63 on Linux";
tag_insight = "Multiple flaws are cause due to,
  - Failure to prevent interpretation of a 'cross-origin' document as a 'CSS'
    stylesheet when the document lacks a CSS token sequence.
  - An error when altering the size of the browser window may cause the wrong
    part of the URL of a web page to be displayed.
  - An error in the handling of reloads and redirects combined with caching may
    result in scripts executing in the wrong security context.
  - Failure to properly verify the origin of video content, which allows remote
    attackers to obtain sensitive information by using a video stream as HTML5
    canvas content.
  - Failure to properly restrict web script in unspecified circumstances involving
    reloads and redirects.
  - Failure to properly select the security context of JavaScript code associated
    with an error page.
  - Error in 'SVG' document in an 'IMG' element.";
tag_solution = "Upgrade to Opera Web Browser version 10.63 or later,
  For updates refer to http://www.opera.com/download/";
tag_summary = "The host is installed with Opera browser and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802731");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2010-4043", "CVE-2010-4044", "CVE-2010-4046", "CVE-2010-4045",
                "CVE-2010-4047", "CVE-2010-4049", "CVE-2010-4048", "CVE-2010-4050");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-04-05 14:23:48 +0530 (Thu, 05 Apr 2012)");
  script_name("Opera Browser Multiple Vulnerabilities October-10 (Linux)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41740");
  script_xref(name : "URL" , value : "http://www.opera.com/support/kb/view/971/");
  script_xref(name : "URL" , value : "http://www.opera.com/docs/changelogs/unix/1063/");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2010/Oct/1024570.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_opera_detection_linux_900037.nasl");
  script_require_keys("Opera/Linux/Version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

## Variable Initialization
operaVer = "";

## Get Opera Version from KB
operaVer = get_kb_item("Opera/Linux/Version");

if(operaVer)
{
  ## Grep for Opera Versions prior to 10.63
  if(version_is_less(version:operaVer, test_version:"10.63")){
    security_message(0);
  }
}
