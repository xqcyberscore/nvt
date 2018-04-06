###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_firefox_js_info_disc_vuln_lin.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Firefox Information Disclosure Vulnerability Jan09 (Linux)
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

tag_impact = "Successful exploitation will let the attacker execute arbitrary
  codes in the context of the web browser and can obtain sensitive information
  of the remote user through the web browser.
  Impact Level: Application";
tag_affected = "Mozilla Firefox version from 2.0 to 3.0.5 on Linux.";
tag_insight = "The Web Browser fails to properly enforce the same-origin policy, which leads
  to cross-domain information disclosure.";
tag_solution = "Upgrade to Mozilla Firefox version 3.6.3 or later
  For updates refer to http://www.getfirefox.com";
tag_summary = "The host is installed with Mozilla Firefox browser and is prone
  to information disclosure vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900449");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-01-28 13:27:12 +0100 (Wed, 28 Jan 2009)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:N/I:P/A:N");
  script_cve_id("CVE-2009-5913");
  script_bugtraq_id(33276);
  script_name("Firefox Information Disclosure Vulnerability Jan09 (Linux)");
  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=480938");
  script_xref(name : "URL" , value : "http://www.trusteer.com/files/In-session-phishing-advisory-2.pdf");

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

firefoxVer = get_kb_item("Firefox/Linux/Ver");
if(!firefoxVer){
  exit(0);
}

# Grep for firefox version from 2.0 to 3.0.5.
if(version_in_range(version:firefoxVer, test_version:"2.0",
                                        test_version2:"3.0.5")){
  security_message(0);
}
