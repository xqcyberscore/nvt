###############################################################################
# OpenVAS Vulnerability Test
# $Id: remote-ApacheOfbiz-defaultPwd.nasl 5016 2017-01-17 09:06:21Z teissa $
#
# This script the Apache Open For Business (Apache OFBiz) default administrator credentials vulnerability
#
# Author:
# Christian Eric Edjenguele <christian.edjenguele@owasp.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 and later,
# as published by the Free Software Foundation
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

CPE = "cpe:/a:apache:open_for_business_project";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.101023");
  script_version("$Revision: 5016 $");
  script_tag(name:"last_modification", value:"$Date: 2017-01-17 10:06:21 +0100 (Tue, 17 Jan 2017) $");
  script_tag(name:"creation_date", value:"2009-04-25 21:03:34 +0200 (Sat, 25 Apr 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Apache Open For Business Weak Password security check");
  script_category(ACT_ATTACK);
  script_copyright("Christian Eric Edjenguele <christian.edjenguele@owasp.org>");
  script_family("Default Accounts");
  script_dependencies("find_service.nasl", "remote-detect-ApacheOfbiz.nasl");
  script_mandatory_keys("ApacheOFBiz/installed");
  script_require_ports("Services/www", 8443);

  script_tag(name:"summary", value:"The remote host is running the Apache OFBiz with default administrator username and password. 
  Apache OFBiz is an Apache Top Level Project. 
  As automation software it comprises a mature suite of enterprise applications that integrate 
  and automate many of the business processes of an enterprise.");
  script_tag(name:"solution", value:"You must change the default settings if you want to run it for
  production purposes, please refer to Apache OFBiz documentation, for further
  information on how to do this");
  script_tag(name:"impact", value:"This allow an attacker to gain administrative access to the remote application");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);

}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );

module = '/webtools/control/login';
report = '';
host = http_host_name( port:port );
postdata = string( "USERNAME=admin&PASSWORD=ofbiz" );

req = string( "POST ", module, " HTTP/1.1\r\n",
              "Content-Type: application/x-www-form-urlencoded\r\n", 
              "Content-Length: ", strlen(postdata), "\r\n",
              "Referer: http://", host, module, "\r\n",
              "Host: ", host, 
              "\r\n\r\n",
              postdata );

res = http_keepalive_send_recv( port:port, data:req );

if( res ) {

  welcomeMsg = egrep( pattern:"Welcome THE ADMIN.*", string:res );

  if( welcomeMsg ) {
    report += "Apache OFBiz said: " + welcomeMsg + "You are using Apache OFBiz with default ADMINISTRATOR username [admin] and pawssord [ofbiz], this can cause security problem in production environment";
  }	
}


if( report ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );