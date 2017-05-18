###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_broadlight_residential_gateway_mult_vuln.nasl 5827 2017-04-03 06:27:11Z cfi $
#
# Broadlight Residential Gateway DI3124 Multiple Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.805596");
  script_version("$Revision: 5827 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-04-03 08:27:11 +0200 (Mon, 03 Apr 2017) $");
  script_tag(name:"creation_date", value:"2015-06-26 10:03:52 +0530 (Fri, 26 Jun 2015)");
  script_name("Broadlight Residential Gateway DI3124 Multiple Vulnerabilities");

  script_tag(name:"summary", value:"This host is running Broadlight Residential
  Gateway and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to read sensitive information or not.");

  script_tag(name: "insight" , value:"Multiple flaws exists as no user
  authentication is required for acessing multiple sensitive pages.");

  script_tag(name: "impact" , value:"Successful exploitation will allow remote
  attackers to change DNS and gain access to potentially sensitive information.

  Impact Level: Application");

  script_tag(name:"affected", value:"Broadlight Residential Gateway DI3124");

  script_tag(name:"solution", value:"No solution or patch was made available
  for at least one year since disclosure of this vulnerability. Likely none will
  be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another
  one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"exploit");

  script_xref(name : "URL" , value : "https://www.exploit-db.com/exploits/37214");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
gatePort = "";
sndReq = "";
rcvRes = "";

gatePort = get_http_port(default:80);

rcvRes = http_get_cache(item: "/", port:gatePort);

## Confirm Application
if(rcvRes && "title>Broadlight Residential Gateway<" >< rcvRes)
{

  ##Construct Attack request
  url = "/cgi-bin/getconf.cgi";

  ## Send ATACK Request
  sndReq = http_get(item: url, port:gatePort);
  rcvRes = http_keepalive_send_recv(port:gatePort, data:sndReq);

  if(rcvRes =~ "<username>.*</username>" && rcvRes =~ "<password>.*</password>")
  {
    security_message(port:gatePort);
    exit(0);
  }
}
