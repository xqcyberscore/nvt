###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_iexplorer_anti_xss_vuln.nasl 684 2008-12-16 12:40:05Z dec$
#
# Microsoft Internet Explorer Anti-XSS Filter Vulnerabilities
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will let the attacker execute arbitrary codes in the
  context of the application and can perform the XSS attacks on the remote hosts
  without any consent of IE.

  Impact Level: Application/Network";

tag_affected = "Windows Platform with Internet Explorer 8.0 Beta 2";

tag_insight = "These flaws are due to,

  - Injections facilitated by some HTTP headers are not currently blocked.

  - Injections into some contexts are not blocked where contents can be
    injected directly into JavaScript without breaking out a string.

  - Allowing access to the attacker to inject XSS string in 2 different HTML
    positions.

  - It lets the attacker execute XSS attacks using CRLF sequence in
    conjunction with a crafted Content-Type header.";

tag_solution = "Solution/Patch not available as on 16th December 2008. For further updates refer,
  http://www.microsoft.com/windows/downloads/ie/getitnow.mspx";

tag_summary = "The host is installed with Internet Explorer and is prone to
  anti-xss filter vulnerabilities.";
if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800208");
  script_version("$Revision: 6527 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-05 07:56:34 +0200 (Wed, 05 Jul 2017) $");
  script_tag(name:"creation_date", value:"2008-12-19 13:40:09 +0100 (Fri, 19 Dec 2008)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_bugtraq_id(32780);
  script_cve_id("CVE-2008-5551", "CVE-2008-5552", "CVE-2008-5553",
                "CVE-2008-5554", "CVE-2008-5555", "CVE-2008-5556");
  script_name("Microsoft Internet Explorer Anti-XSS Filter Vulnerabilities");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/499124");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/0812-exploits/ie80-xss.txt");
  script_xref(name : "URL" , value : "http://www.webappsec.org/lists/websecurity/archive/2008-12/msg00057.html");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

if( !ieVer = get_kb_item("MS/IE/Version") ) exit( 0 );

#Check for Internet Explorer 8.0 to 8.0.6001.18241
if(version_in_range(version:ieVer, test_version:"8.0",
                                  test_version2:"8.0.6001.18241")){
  security_message(0);
}
