###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_shibboleth_sp_mult_xss_vuln_win.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Shibboleth Service Provider Multiple XSS Vulnerabilities (Windows)
#
# Authors:
# Sharath S <sharaths@secpod.com>
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

tag_impact = "Successful exploitation could allow remote attackers to inject arbitrary web
  script or HTML via URLs that are encountered in redirections, and appear in
  automatically generated forms.
  Impact Level: Application.";
tag_affected = "Shibboleth Service Provider version 1.3.x before 1.3.5 and 2.x before 2.3
  on Windows.";
tag_insight = "The flaws are due to an error within the sanitation of certain URLs.
  This can be exploited to insert arbitrary HTML and script code, which will
  be executed in a user's browser session in the context of an affected site
  when malicious data is viewed.";
tag_solution = "Upgrade Shibboleth Service Provider version 1.3.5 or 2.3 or later.
  http://shibboleth.internet2.edu/downloads.html";
tag_summary = "The host has Shibboleth Service Provider installed and is prone to
  multiple Cross-Site Scripting vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801148");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-11-13 15:48:12 +0100 (Fri, 13 Nov 2009)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-3300");
  script_name("Shibboleth Service Provider Multiple XSS Vulnerabilities (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/37237/");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/54140");
  script_xref(name : "URL" , value : "http://shibboleth.internet2.edu/secadv/secadv_20091104.txt");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_shibboleth_sp_detect_win.nasl", "http_version.nasl");
  script_require_keys("Shibboleth/SP/Win/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

port = 1600;
if(!get_port_state(port)){
  exit(0);
}

shibVer = get_kb_item("Shibboleth/SP/Win/Ver");
if(!shibVer){
  exit(0);
}

# Check for Shibboleth Service Provider version 1.3.x < 1.3.5 and 2.x < 2.3
if(version_in_range(version:shibVer, test_version:"1.3", test_version2:"1.3.4")||
   version_in_range(version:shibVer, test_version:"2.0", test_version2:"2.2")){
  security_message(port);
}
