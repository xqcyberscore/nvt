###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_thunderbird_mult_vuln_jun09_lin.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Mozilla Thunderbird Multiple Vulnerabilities Jun-09 (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation could result in remote arbitrary JavaScript code
  execution, spoofing attacks, sensitive information disclosure, and can cause
  denial of service.
  Impact Level: System/Application";
tag_affected = "Thunderbire version prior to 2.0.0.22 on Linux.";
tag_insight = "- Error in js/src/xpconnect/src/xpcwrappedjsclass.cpp file will allow attacker
    to execute arbitrary web script.
  - An error when handling a non-200 response returned by a proxy in reply to a
    CONNECT request, which could cause the body of the response to be rendered
    within the context of the request 'Host:' header.
  - An error when handling event listeners attached to an element whose owner
    document is null.
  - Due to content-loading policies not being checked before loading external
    script files into XUL documents, which could be exploited to bypass
    restrictions.
  - An error when handling event listeners attached to an element whose owner
    document is null.
  - Error exists in JavaScript engine is caused via vectors related to
    js_LeaveSharpObject, ParseXMLSource, and a certain assertion in jsinterp.c.
  - Error exists via vectors involving 'double frame construction.'";
tag_solution = "Upgrade to Firefox version 2.0.0.22
  http://www.mozilla.com/en-US/thunderbird/all.html";
tag_summary = "The host is installed with Thunderbird, which is prone to multiple
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800639");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-06-16 15:11:01 +0200 (Tue, 16 Jun 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1832", "CVE-2009-1833", "CVE-2009-1836", "CVE-2009-1838",
                "CVE-2009-1840", "CVE-2009-1841", "CVE-2009-1392");
  script_bugtraq_id(35326);
  script_name("Mozilla Thunderbird Multiple Vulnerability Jun-09 (Linux)");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/1572");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2009/mfsa2009-24.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2009/mfsa2009-27.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2009/mfsa2009-29.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2009/mfsa2009-31.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2009/mfsa2009-32.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_thunderbird_detect_lin.nasl");
  script_require_keys("Thunderbird/Linux/Ver");
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

thunderbirdVer = get_kb_item("Thunderbird/Linux/Ver");
# Check for Thunderbird Version < 2.0.0.22
if(thunderbirdVer != NULL)
{
  if(version_is_less(version:thunderbirdVer ,test_version:"2.0.0.22")){
    security_message(0);
  }
}
