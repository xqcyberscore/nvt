###############################################################################
# OpenVAS Vulnerability Test
# $Id: remote-Opentaps-defaultPwd.nasl 9857 2018-05-16 08:38:18Z cfischer $
#
# This script the Opentaps ERP + CRM default administrator credentials vulnerability
#
# remote-Opentaps-defaultPwd.nasl
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:apache:opentaps";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.101024");
  script_version("$Revision: 9857 $");
  script_tag(name:"last_modification", value:"$Date: 2018-05-16 10:38:18 +0200 (Wed, 16 May 2018) $");
  script_tag(name:"creation_date", value:"2009-04-25 22:17:58 +0200 (Sat, 25 Apr 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Opentaps ERP + CRM Weak Password security check");
  script_category(ACT_ATTACK);
  script_copyright("Christian Eric Edjenguele <christian.edjenguele@owasp.org>");
  script_family("Web application abuses");
  script_dependencies("remote-detect-Opentaps_ERP_CRM.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("OpentapsERP/installed");

  script_tag(name:"summary", value:"The remote host is running the Apache OFBiz with default administrator username and password.
  Opentaps is a full-featured ERP + CRM suite which incorporates several open source projects,
  including Apache Geronimo, Tomcat, and OFBiz for the data model and transaction framework.
  Pentaho and JasperReports for business intelligence. Funambol for mobile device and Outlook integration.
  and the opentaps applications which provide user-driven applications for CRM, accounting and finance,
  warehouse and manufacturing, and purchasing and supply chain mmanagement.");

  script_tag(name:"solution", value:"You must change the default settings if you want to run it for
  production purposes, please refer to the Opentaps ERP + CRM documentation, for
  further information on how to do this.");

  script_tag(name:"impact", value:"This allow an attacker to gain administrative access to the remote application.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port(cpe:CPE) ) exit(0);
get_app_location(port:port, cpe:CPE, nofork:TRUE); # To have a reference to the Detection-NVT

module = '/webtools/control/login';
report = '';
host = http_host_name(port:port);
postdata = string("USERNAME=admin&PASSWORD=ofbiz");

req = string("POST ", module, " HTTP/1.1\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: ", strlen(postdata), "\r\n",
             "Referer: http://", host, module, "\r\n",
             "Host: ", host,
             "\r\n\r\n",
             postdata);
res = http_keepalive_send_recv(port:port, data:res);
if(!res) exit(0);

welcomeMsg = egrep(pattern:"Welcome THE ADMIN.*", string:res);
if(welcomeMsg){
  report += "Opentaps ERP + CRM said: " + welcomeMsg + "this application is running using default ADMINISTRATOR username [admin] and password [ofbiz], this can cause security problem in production environment";
}

if(strlen(report) > 0) {
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
