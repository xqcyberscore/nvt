###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_joomnik_comp_album_param_sql_inj_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Joomla! com_joomnik Component 'album' Parameter SQL Injection Vulnerability
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow attacker to perform SQL
Injection attack and gain sensitive information.

Impact Level: Application";

tag_affected = "Joomla! Joomnik Gallery Component Version 0.9. Other versions
may also be affected.";

tag_insight = "The flaw is caused by improper validation of user-supplied input
via the 'album' parameter to 'index.php', which allows attackers to manipulate
SQL queries by injecting arbitrary SQL code.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with Joomla! with Joomnik Gallery Component
and is prone to SQL injection vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802022");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-06-07 13:29:28 +0200 (Tue, 07 Jun 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Joomla! com_joomnik Component 'album' Parameter SQL Injection Vulnerability");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17341/");
  script_xref(name : "URL" , value : "http://extensions.joomla.org/extensions/photos-a-images/photo-gallery/251");

  script_tag(name:"qod_type", value:"remote_active");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("joomla/installed");
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
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Get Joomla Directory
if(!dir = get_dir_from_kb(port:port,app:"joomla")) {
  exit(0);
}

## Construct the Attack Request
url = string(dir, "/index.php?option=com_joomnik&album='SQLi");

## Try attack and check the response to confirm vulnerability
if(http_vuln_check(port:port, url:url, pattern:'>You have an error in your' +
                                       ' SQL syntax;', check_header: FALSE)){
  security_message(port);
}
