###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_google_chrome_info_dis_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Google Chrome Information Disclosure Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
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

tag_impact = "Successful exploitation will let the attacker execute arbitrary codes in
  the context of the web browser and can reveal sensitive information of the
  remote user through the web browser.";
tag_affected = "Google Chrome version 1.0.154.43 and prior.";
tag_insight = "This flaw is due to cross-domain information disclosure vulnerability as
  the web browser fails to properly enforce the same-origin policy.";
tag_solution = "No solution or patch was made available for at least one year since disclosure
  of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.
  For updates refer to http://googlechromereleases.blogspot.com";
tag_summary = "This host is installed with Google Chrome and is prone to
  information disclosure vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900439");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-01-22 12:00:13 +0100 (Thu, 22 Jan 2009)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:N/I:P/A:N");
  script_cve_id("CVE-2008-5915");
  script_bugtraq_id(33276);
  script_name("Google Chrome Information Disclosure Vulnerability");
  script_xref(name : "URL" , value : "http://www.trusteer.com/files/In-session-phishing-advisory-2.pdf");
  script_xref(name : "URL" , value : "http://www.darkreading.com/security/attacks/showArticle.jhtml?articleID=212900161");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("gb_google_chrome_detect_win.nasl");
  script_require_keys("GoogleChrome/Win/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(!chromeVer){
  exit(0);
}

if(version_is_less_equal(version:chromeVer, test_version:"1.0.154.43")){
  security_message(0);
}
