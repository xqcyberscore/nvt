###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mahara_info_disc_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Mahara Information Disclosure Vulnerability
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

tag_impact = "Successful exploitation will allow attacker to gain sensitive information
  in the affected web application.
  Impact Level: Application";
tag_affected = "Mahara version 1.1 before 1.1.5";
tag_insight = "- The application fails to apply permission checks when saving a view that 
    contains artefacts, which allows remote authenticated users to read
    another user's artefact.";
tag_solution = "Upgrade to Mahara version 1.1.5 or later
  https://eduforge.org/projects/mahara/";
tag_summary = "This host is running Mahara and is prone to Information Disclosure
  Vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900383");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-06-26 07:55:21 +0200 (Fri, 26 Jun 2009)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_cve_id("CVE-2009-2171");
  script_name("Mahara Information Disclosure Vulnerability");
  script_xref(name : "URL" , value : "http://mahara.org/interaction/forum/topic.php?id=753");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_mahara_detect.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

maharaPort = get_http_port(default:80);
if(!maharaPort){
  exit(0);
}

maharaVer = get_kb_item("www/"+ maharaPort + "/Mahara");
if(!maharaVer){
  exit(0);
}

ver = eregmatch(pattern:"^(.+) under (/.*)$", string:maharaVer);
if(ver[1] != NULL)
{
  # Check for Mahara version 1.1 < 1.1.5
  if(version_in_range(version:ver[1], test_version:"1.1",
                                      test_version2:"1.1.4")){
    security_message(maharaPort);
  }
}
