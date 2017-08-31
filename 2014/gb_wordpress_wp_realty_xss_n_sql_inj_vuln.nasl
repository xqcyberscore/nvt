###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_wp_realty_xss_n_sql_inj_vuln.nasl 33822 2014-01-02 15:02:10Z Jan$
#
# WordPress WP Realty Plugin 'listing_id' XSS and SQL Injection Vulnerabilities
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804054";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6663 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-07-11 11:58:05 +0200 (Tue, 11 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-01-02 15:02:10 +0530 (Thu, 02 Jan 2014)");
  script_name("WordPress WP Realty Plugin 'listing_id' XSS and SQL Injection Vulnerabilities");

  tag_summary =
"This host is installed with Wordpress WP Realty Plugin and is prone to
multiple vulnerabilities.";

  tag_vuldetect =
"Send a crafted data via HTTP GET request and check whether it is able to read
cookie or not.";

  tag_insight =
"Input passed via the 'listing_id' parameter to index_ext.php script is
not properly sanitized before being returned to the user.";

  tag_impact =
"Successful exploitation will allow attacker to execute arbitrary HTML and
script code in a user's browser session in the context of an affected site
or execute arbitrary SQL commands in applications database and gain complete
control over the vulnerable web application.

Impact Level: Application";

  tag_affected =
"WordPress WP Realty plugin.";

  tag_solution =
"No Solution or patch is available as of 3rd January, 2014. Information
regarding this issue will be updated once the solution details are available.
For updates refer to http://wprealty.org";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"solution_type", value:"NoneAvailable");

  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/29021");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/124418");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/wordpress-wp-realty-cross-site-scripting");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

## Variable Initialization
http_port = 0;
dir = "";
url = "";

## Get HTTP Port
if(!http_port = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Get WordPress Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:http_port)){
  exit(0);
}

## Construct the attack request
url = dir + '/wp-content/plugins/wp-realty/index_ext.php?action='+
            'contact_friend&popup=yes&listing_id="/><script>aler'+
                                   't(document.cookie);</script>';

## Extra check is not possible
if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
   pattern:"<script>alert\(document.cookie\);</script>"))
{
  security_message(http_port);
  exit(0);
}
