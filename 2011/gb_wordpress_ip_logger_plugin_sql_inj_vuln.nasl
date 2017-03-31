###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_ip_logger_plugin_sql_inj_vuln.nasl 3108 2016-04-19 06:58:41Z benallard $
#
# WordPress IP Logger Plugin map-details.php SQL Injection Vulnerability
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

tag_affected = "WordPress IP Logger Version 3.0, Other versions may also be
affected.";

tag_insight = "The flaw is due to improper validation of user-supplied input
passed via multiple parameters to '/wp-content/plugins/ip-logger/map-details.php',
which allows attackers to manipulate SQL queries by injecting arbitrary
SQL code.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with WordPress IP Logger plugin and is
prone to sql injection vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802035";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 3108 $");
  script_tag(name:"last_modification", value:"$Date: 2016-04-19 08:58:41 +0200 (Tue, 19 Apr 2016) $");
  script_tag(name:"creation_date", value:"2011-09-16 17:22:17 +0200 (Fri, 16 Sep 2011)");
  script_bugtraq_id(49168);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("WordPress IP Logger Plugin map-details.php SQL Injection Vulnerability");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/69255");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17673");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/104086");

  script_tag(name:"qod_type", value:"remote_active");
  script_summary("Check if WordPress IP Logger plugin is vulnerable to SQL Injection");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("wordpress/installed");
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
include("host_details.inc");


## Get HTTP Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get WordPress Installed Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

## Construct the Attack Request
url = dir + "/wp-content/plugins/ip-logger/map-details.php?lat=-1'[SQLi]--";

## Try attack and check the response to confirm vulnerability.
if(http_vuln_check(port:port, url:url, pattern:"mysql_fetch_assoc\(\): suppli"+
   "ed argument is not a valid MySQL result|You have an error in your SQL " +
   "syntax;")){
  security_message(port);
  exit(0);
}
