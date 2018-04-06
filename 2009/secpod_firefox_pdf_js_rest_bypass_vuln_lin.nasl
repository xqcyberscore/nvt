###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_firefox_pdf_js_rest_bypass_vuln_lin.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Mozilla Firefox PDF Javascript Restriction Bypass Vulnerability (Linux)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will let attacker execute arbitrary codes in the
  context of the malicious PDF file and execute arbitrary codes into the context
  of the remote system.
  Impact Level: Application";
tag_affected = "Firefox version 3.0.10 and prior on Linux.";
tag_insight = "Error while executing DOM calls in response to a javascript: URI in the target
  attribute of a submit element within a form contained in an inline PDF file
  which causes bypassing restricted Adobe's JavaScript restrictions.";
tag_solution = "Upgrade to Mozilla Firefox version 3.6.3 or later
  For updates refer to http://www.mozilla.com/en-US/index.html";
tag_summary = "The host is installed with Mozilla Firefox browser and is prone to
  PDF Javascript Restriction Bypass Vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900351");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-05-18 09:37:31 +0200 (Mon, 18 May 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1597");
  script_name("Mozilla Firefox PDF JavaScript Restriction Bypass Vulnerability (Linux)");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/503183/100/0/threaded");
  script_xref(name : "URL" , value : "http://secniche.org/papers/SNS_09_03_PDF_Silent_Form_Re_Purp_Attack.pdf");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_require_keys("Firefox/Linux/Ver");
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

ffVer = get_kb_item("Firefox/Linux/Ver");
if(ffVer == NULL){
  exit(0);
}

# Grep for Firefox version <= 3.0.10
if(version_is_less_equal(version:ffVer, test_version:"3.0.10")){
  security_message(0);
}
