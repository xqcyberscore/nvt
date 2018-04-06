###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_robohelp_server_unspecified_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Adobe RoboHelp Server Unspecified Vulnerability
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

tag_impact = "Successful exploitation could allow attackers to execute
arbitrary code or compromise a vulnerable system.

Impact Level: Application";

tag_affected = "Adobe RoboHelp Server version 8.0";

tag_insight = "The flaw is due to an unspecified 'pre-authentication' error
which can be exploited via unknown vectors.";

tag_solution = "Vendor has released a patch to fix the issue, refer below link
for patch,
http://www.adobe.com/support/security/advisories/apsa09-05.html
For updates refer to http://www.adobe.com/";

tag_summary = "This host is running Adobe RoboHelp Server and is prone to unspecified
vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801103");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-09-10 15:23:12 +0200 (Thu, 10 Sep 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-3068");
  script_bugtraq_id(36245);
  script_name("Adobe RoboHelp Server Unspecified Vulnerability");
  script_xref(name : "URL" , value : "http://intevydis.com/vd-list.shtml");
  script_xref(name : "URL" , value : "http://www.intevydis.com/blog/?p=26");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/36467");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/advisories/apsa09-05.html");
  script_xref(name : "URL" , value : "http://blogs.adobe.com/psirt/2009/09/potential_robohelp_server_8_is.html");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_robohelp_server_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

robohelpPort = get_http_port(default:8080);
if(!robohelpPort)
{
  exit(0);
}

robohelpVer = get_kb_item("www/" + robohelpPort + "/RoboHelpServer");
robohelpVer = eregmatch(pattern:"^(.+) under (/.*)$", string:robohelpVer);

if(robohelpVer[1] != NULL)
{
  if(version_is_equal(version:robohelpVer[1], test_version:"8.0")){
    security_message(robohelpPort);
  }
}
