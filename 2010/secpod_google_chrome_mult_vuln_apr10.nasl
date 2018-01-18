###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_google_chrome_mult_vuln_apr10.nasl 8447 2018-01-17 16:12:19Z teissa $
#
# Google Chrome Multiple Vulnerabilities (win)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-05-10
#  Added the related CVE and description
#
# Updated By: Sooraj KS <kssooraj@secpod.com> on 2010-09-28
#  Added the related CVE
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow attacker to obtain sensitive information,
  execute arbitrary code in the context of the browser, bypass certain security
  restrictions.
  Impact Level: Application";
tag_affected = "Google Chrome version prior to 4.1.249.1059 on windows";
tag_insight = "Multiple flaws are due to:
  - Type confusion error with 'forms'
  - An unspecified error in the handling of 'HTTP requests', which leads to
    cross-site request forgery attacks.
  - An error related to 'chrome://net-internals' and 'chrome://downloads',
    which leads to cross-site scripting attacks
  - Error related to local file references through 'developer tools'
  - Pages that might load with privileges of the 'New Tab page'.
  - An unspecified error in 'V8 bindings' causes a denial of service";
tag_solution = "Upgrade to the version 4.1.249.1059 or later,
  For updates refer to http://www.google.com/chrome";
tag_summary = "This host is installed with Google Chrome Web Browser and is prone
  to multiple vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902050");
  script_version("$Revision: 8447 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-17 17:12:19 +0100 (Wed, 17 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-04-30 15:20:35 +0200 (Fri, 30 Apr 2010)");
  script_cve_id("CVE-2010-1502", "CVE-2010-1767", "CVE-2010-1500", "CVE-2010-1503",
                "CVE-2010-1504", "CVE-2010-1505", "CVE-2010-1506", "CVE-2010-1767");
  script_bugtraq_id(39603);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Google Chrome Multiple Vulnerabilities (win)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/39544");
  script_xref(name : "URL" , value : "http://googlechromereleases.blogspot.com/2010/04/stable-update-security-fixes.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (c) 2010 SecPod");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_win.nasl");
  script_require_keys("GoogleChrome/Win/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

gcVer = get_kb_item("GoogleChrome/Win/Ver");
if(!gcVer){
  exit(0);
}

# Check for google chrome Version less than 4.1.249.1059
if(version_is_less(version:gcVer, test_version:"4.1.249.1059")){
  security_message(0);
}
