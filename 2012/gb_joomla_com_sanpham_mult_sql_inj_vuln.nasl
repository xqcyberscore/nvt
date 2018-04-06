##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_com_sanpham_mult_sql_inj_vuln.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Joomla Sanpham Component Multiple SQL Injection Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will let attackers to manipulate SQL
queries by injecting arbitrary SQL code.

Impact Level: Application";

tag_affected = "Joomla Sanpham Component";

tag_insight = "The flaws are due to input passed via the 'kindid', 'cid',
and 'modelsid' parameters to 'index.php' is not properly sanitised before
being used in a SQL query.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is running Joomla Sanpham component and is prone to
multiple SQL injection vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802568");
  script_version("$Revision: 9352 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-01-23 15:38:16 +0530 (Mon, 23 Jan 2012)");
  script_name("Joomla Sanpham Component Multiple SQL Injection Vulnerabilities");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/108916/joomlasanpham-sql.txt");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_active");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("joomla/installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

## Get the port
joomlaPort = get_http_port(default:80);
if(!joomlaPort){
  exit(0);
}

## Get the application directiory
if(!joomlaDir = get_dir_from_kb(port:joomlaPort, app:"joomla")){
  exit(0);
}

## Construct attack request
url = joomlaDir + "/index.php?option=com_sanpham&view=sanpham&kindid='";

## Check the response to confirm vulnerability
if(http_vuln_check(port:joomlaPort, url:url, pattern:
                           "You have an error in your SQL syntax;")){
  security_message(joomlaPort);
}
