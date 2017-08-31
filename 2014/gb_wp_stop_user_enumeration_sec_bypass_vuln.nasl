###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wp_stop_user_enumeration_sec_bypass_vuln.nasl 34987 2014-02-05 13:09:46Z Jan$
#
# WordPress Stop User Enumeration Security Bypass Vulnerability
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804084";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6637 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 11:58:13 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-02-05 13:09:46 +0530 (Wed, 05 Feb 2014)");
  script_name("WordPress Stop User Enumeration Security Bypass Vulnerability");

  tag_summary =
"This host is installed with WordPress Stop User Enumeration Plugin and is
prone to security bypass vulnerability.";

  tag_vuldetect =
"Send a crafted data via HTTP POST request and check whether it is able to
bypass security restriction or not.";

  tag_insight =
"Username enumeration protection for 'author' parameter via POST request
is not proper.";

  tag_impact =
"Successful exploitation will allow attacker to enumerate users and get some
sensitive information, leads to further attacks.

Impact Level: Application";

  tag_affected =
"WordPress Stop User Enumeration Plugin version 1.2.4, Other versions may also
be affected.";

  tag_solution =
"No Solution or patch is available as of 5th February, 2014. Information
regarding this issue will be updated once the solution details are available.
For updates refer to http://wordpress.org/plugins/stop-user-enumeration";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"solution_type", value:"NoneAvailable");

  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2014/Feb/3");
  script_xref(name : "URL" , value : "http://www.securelist.com/en/advisories/56643");
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/fulldisclosure/current/0003.html");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/wordpress-stop-user-enumeration-124-bypass");
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

## Confirm the Plugin Installation
url = dir + '/wp-content/plugins/stop-user-enumeration/stop-user-enumeration.php';
if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
   pattern:"<b>Fatal error</b>:  Call to undefined function "+
           "is_admin().*stop-user-enumeration.php</b>"))
{
  url = dir + '/index.php?author=1';

  ## Check Plugin is Working properly for Get Request
  if(http_vuln_check(port:http_port, url:url, check_header:'FALSE',
     pattern:"HTTP/1.. 500 Internal Server Error", extra_check:'>forbidden<'))
  {
    ## Check Plugin is Working on POST Request
    sndReq = string("POST ", dir,"/index.php HTTP/1.1\r\n",
                    "Host: ", get_host_name(), "\r\n",
                    "Content-Type: application/x-www-form-urlencoded\r\n",
                    "Content-Length: 8\r\n",
                    "\r\nauthor=1\r\n");

    ## Send request and receive the response
    rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);

    ## Confirm POST Request is Blocked or Not
    if(rcvRes =~ "HTTP/1.. 200 OK" && '>forbidden<' >!< rcvRes &&
       rcvRes !~ "HTTP/1.. 500 Internal Server Error")
    {
      security_message(http_port);
      exit(0);
    }
  }
}
