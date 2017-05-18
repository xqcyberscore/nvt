###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_related_posts_exit_popup_sql_inj_vuln.nasl 5999 2017-04-21 09:02:32Z teissa $
#
# WordPress Related Posts Exit Popup Plugin SQL Injection Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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

tag_impact = "Successful exploitation will allow attackers to manipulate SQL
queries by injecting arbitrary SQL code and gain sensitive information.

Impact Level: Application";

tag_affected = "WordPress Related Posts Exit Popup Plugin";

tag_insight = "Input passed via the 'id' parameter to
/wp-content/plugins/related_posts_exit_popup/related_posts_exit_popup_window.php
is not properly sanitised before being used in a SQL query.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is running WordPress Related Posts Exit Popup Plugin
and is prone to sql injection vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803050";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 5999 $");
  script_tag(name:"last_modification", value:"$Date: 2017-04-21 11:02:32 +0200 (Fri, 21 Apr 2017) $");
  script_tag(name:"creation_date", value:"2012-11-16 15:16:37 +0530 (Fri, 16 Nov 2012)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("WordPress Related Posts Exit Popup Plugin SQL Injection Vulnerability");
  script_xref(name : "URL" , value : "http://cxsecurity.com/issue/WLB-2012110073");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/118026/wprpep-sql.txt");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_active");
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
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

##
## The script code starts here
##

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Variable Initialization
port = 0;
url = "";
dir = "";

## Get HTTP Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

## Check Host Supports PHP
if(!can_host_php(port:port)) exit(0);

## Get WordPress Installed Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

## Construct XSS attack request
url = dir + '/wp-content/plugins/related_posts_exit_popup/' +
            'related_posts_exit_popup_window.php?id=1"';

## Confirm exploit worked properly or not
if(http_vuln_check(port:port, url:url, check_header:TRUE,
                   pattern:"You have an error in your SQL syntax;",
                   extra_check:">WordPress database error"))
{
  security_message(port:port);
  exit(0);
}
