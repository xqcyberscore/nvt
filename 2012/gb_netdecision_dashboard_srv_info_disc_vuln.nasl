###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netdecision_dashboard_srv_info_disc_vuln.nasl 5988 2017-04-20 09:02:29Z teissa $
#
# Netmechanica NetDecision Dashboard Server Information Disclosure Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802703");
  script_version("$Revision: 5988 $");
  script_cve_id("CVE-2012-1464");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-04-20 11:02:29 +0200 (Thu, 20 Apr 2017) $");
  script_tag(name:"creation_date", value:"2012-03-08 17:47:52 +0530 (Thu, 08 Mar 2012)");
  script_name("Netmechanica NetDecision Dashboard Server Information Disclosure Vulnerability");

  script_xref(name : "URL" , value : "http://secpod.org/blog/?p=478");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18543/");
  script_xref(name : "URL" , value : "http://secpod.org/exploits/SecPod_Netmechanica_NetDecision_Dashboard_Server_Info_Disc_PoC.py");
  script_xref(name : "URL" , value : "http://secpod.org/advisories/SecPod_Netmechanica_NetDecision_Dashboard_Server_Info_Disc_Vuln.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_require_ports("Services/www", 8090);
  script_dependencies("find_service.nasl", "http_version.nasl");

  script_tag(name : "impact" , value : "Successful exploitation will allow attackers to gain sensitive information.
  Impact Level: Application");
  script_tag(name : "affected" , value : "NetDecision Dashboard Server version 4.5.1");
  script_tag(name : "insight" , value : "The flaw is due to an improper validation of malicious HTTP request
  appended with '?' character, which discloses the Dashboard server's web script
  physical path.");
  script_tag(name : "solution" , value : "Upgrade to NetDecision Dashboard Server 4.6.1 or later,
  For updates refer to http://www.netmechanica.com/downloads/");
  script_tag(name : "summary" , value : "This host is running NetDecision Dashboard Server and is prone to
  information disclosure vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
port = 0;
sndReq = "";
rcvRes = "";
sndReq1 = "";
rcvRes1 = "";

## Check Port status
port = get_http_port(default:8090);

## Confirm the application
rcvRes = http_get_cache(item:"/", port:port);

if(!rcvRes || ("Server: NetDecision-HTTP-Server" >!< rcvRes &&
   !egrep(pattern:">Copyright .*NetMechanica", string:rcvRes))){
  exit(0);
}

sndReq1 = http_get(item:"/?", port:port);
rcvRes1 = http_keepalive_send_recv(port:port, data:sndReq1);
if(!rcvRes1){
  exit(0);
}

## Check for the path of DashboardServer in response
if(egrep(pattern:"^HTTP/.* 200 OK", string:rcvRes1) &&
   egrep(pattern:"Failed to open script file: .?:\\.*NetDecision\\" +
            "Script Folders\\DashboardServer", string:rcvRes1)){
  security_message(port:port);
  exit(0);
}

exit(99);
