###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_opera_mult_vuln_dec08_lin.nasl 9349 2018-04-06 07:02:25Z cfischer $
#
# Opera Web Browser Multiple Vulnerabilities - Dec08 (Linux)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (c) 2008 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_impact = "Successful remote attack could inject arbitrary code, information disclosure,
  execute java or plugin content and can even crash the application.
  Impact Level: Application";
tag_affected = "Opera version prior to 9.63 on Linux.";
tag_insight = "The flaws are due to
  - a buffer overflow error when handling certain text-area contents.
  - a memory corruption error when processing certain HTML constructs.
  - an input validation error in the feed preview feature when processing URLs.
  - an error in the built-in XSLT templates that incorrectly handle escaped
    content.
  - an error which could be exploited to reveal random data.
  - an error when processing SVG images embedded using img tags.";
tag_solution = "Upgrade to Opera 9.63
  http://www.opera.com/download/";
tag_summary = "The host is installed with Opera web browser and is prone to
  multiple Vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900082");
  script_version("$Revision: 9349 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2008-12-26 14:23:17 +0100 (Fri, 26 Dec 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-5679", "CVE-2008-5680", "CVE-2008-5681",
                "CVE-2008-5682", "CVE-2008-5683");
  script_bugtraq_id(32864);
  script_name("Opera Web Browser Multiple Vulnerabilities - Dec08 (Linux)");
  script_xref(name : "URL" , value : "http://www.opera.com/support/kb/view/920/");
  script_xref(name : "URL" , value : "http://www.opera.com/support/kb/view/921/");
  script_xref(name : "URL" , value : "http://www.opera.com/support/kb/view/923/");
  script_xref(name : "URL" , value : "http://www.opera.com/support/kb/view/924/");
  script_xref(name : "URL" , value : "http://www.opera.com/docs/changelogs/linux/963/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_opera_detection_linux_900037.nasl");
  script_mandatory_keys("Opera/Linux/Version");
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

operaVer = get_kb_item("Opera/Linux/Version");
if(!operaVer){
  exit(0);
}

if(version_is_less(version:operaVer, test_version:"9.63")){
  security_message(0);
}
