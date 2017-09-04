###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_netsaro_messenger_server_info_disc_vuln_vuln.nasl 7029 2017-08-31 11:51:40Z teissa $
#
# NetSaro Enterprise Messenger Server Source Code Disclosure Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902472");
  script_version("$Revision: 7029 $");
  script_tag(name:"last_modification", value:"$Date: 2017-08-31 13:51:40 +0200 (Thu, 31 Aug 2017) $");
  script_tag(name:"creation_date", value:"2011-08-29 16:22:41 +0200 (Mon, 29 Aug 2011)");
  script_cve_id("CVE-2011-3694");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("NetSaro Enterprise Messenger Server Source Code Disclosure Vulnerability");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/104454/SERT-VDN-1012.txt");
  script_xref(name : "URL" , value : "http://www.solutionary.com/index/SERT/Vuln-Disclosures/NetSaro-Enterprise-Messenger-Source-Code.html");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 SecPod");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 4990);
  script_family("General");
  script_tag(name : "impact" , value : "Successful exploitation could allow local attackers to obtain
  access to the source code for the application and use information found to
  conduct further attacks against the application.

  Impact Level: Application");
  script_tag(name : "affected" , value : "NetSaro Enterprise Messenger Server version 2.0 and prior.");
  script_tag(name : "insight" , value : "The flaw exists due to error in administration console, allowing
  a remote attacker to obtain unauthenticated access to the applications source
  code. Attackers may make HTTP GET requests and append a Null Byte (%00) to
  allow download of the source code for the applications web pages.");
  script_tag(name : "solution" , value : "No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");
  script_tag(name : "summary" , value : "The host is running NetSaro Enterprise Messenger Server and is
  prone to source code disclosure vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Check for the default port
port = get_http_port(default:4990);

## Send the request and receive response
rcvRes = http_get_cache(item:"/", port:port);

## Confirm the server
if("<title>NetSaro Administration Console</title>" >< rcvRes)
{
  ## Construct the request with null byte
  sndReq = http_get(item:"/server-summary.nsp%00", port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

  ## Check for the source code of server-summary.nsp
  if(">System Summary</" >< rcvRes &&  ">Product Information</" >< rcvRes){
      security_message(port:port);
      exit(0);
  }
}

exit(99);