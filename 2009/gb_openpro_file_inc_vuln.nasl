###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openpro_file_inc_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# OpenPro Remote File Inclusion Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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

tag_impact = "Attackers can exploit this issue to execute arbitrary code by
including remote PHP files via malicious URLs.

Impact Level: Application";

tag_affected = "OpenPro version 1.3.1 and prior.";

tag_insight = "The user supplied input passed into 'LIBPATH' parameter in the
'search_wA.php' script is not properly sanitised before being returned to the
user.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with OpenPro and is prone to Remote File
Inclusion vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800929");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-09-07 19:45:38 +0200 (Mon, 07 Sep 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-7087");
  script_bugtraq_id(30264);
  script_name("OpenPro Remote File Inclusion Vulnerability");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/494426/100/0/threaded");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_openpro_detect.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

openPort = get_http_port(default:80);
if(!openPort){
  exit(0);
}

openproVer = get_kb_item("www/" + openPort + "/OpenPro");
openproVer = eregmatch(pattern:"^(.+) under (/.*)$", string:openproVer);

if(openproVer[1] != NULL)
{
  if(version_is_less_equal(version:openproVer[1], test_version:"1.3.1")){
    security_message(openPort);
  }
}
