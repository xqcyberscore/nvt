###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_berta_cms_file_upload_vuln.nasl 2583 2016-02-05 08:40:30Z benallard $
#
# Berta CMS Arbitrary File Upload Vulnerability
#
# Authors:
# Deependra Bapna <bdeependra@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.805356");
  script_version("$Revision: 2583 $");
  script_cve_id("CVE-2015-2780");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2016-02-05 09:40:30 +0100 (Fri, 05 Feb 2016) $");
  script_tag(name:"creation_date", value:"2015-04-07 12:32:43 +0530 (Tue, 07 Apr 2015)");
  script_name("Berta CMS Arbitrary File Upload Vulnerability");

  script_tag(name: "summary" , value: "This host is installed with Berta CMS
  is prone to file upload vulnerability.");

  script_tag(name: "vuldetect" , value: "Send a crafted data via HTTP GET request
  and check whether it is is able to upload file or not.");

  script_tag(name: "insight" , value: "The flaw is due to an input passed via
  the 'uploads.php' script is not properly sanitised before being used.");

  script_tag(name: "impact" , value: "Successful exploitation will allow
  remote attackers to utilize various admin functionality, execute any
  arbitrary script, and expose potentially sensitive information.

  Impact Level: Application.");

  script_tag(name: "affected" , value:"Berta CMS version before 0.8.10b.");

  script_tag(name: "solution" , value:"Upgrade to Berta CMS version 0.8.10b
  or later, For updates refer to http://www.berta.me");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"exploit");

  script_xref(name: "URL" , value : "http://seclists.org/fulldisclosure/2015/Mar/155");
  script_xref(name: "URL" , value : "http://www.openwall.com/lists/oss-security/2015/03/30/7");
  script_xref(name: "URL" , value : "http://packetstormsecurity.com/files/131041/Berta-CMS-File-Upload-Bypass.html");

  script_summary("Check if Berta CMS is vulnerable to file upload vulnerability.");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
url = "";
dir = "";
sndReq = "";
rcvRes = "";
http_port = "";

## Get HTTP Port
http_port = get_http_port(default:80);
if(!http_port){
  http_port = 80;
}

## Check the port status
if(!get_port_state(http_port)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:http_port)){
  exit(0);
}
## Iterate over possible paths
foreach dir (make_list_unique("/", "/engine", "/berta/engine", "/berta", cgi_dirs()))
{

  if( dir == "/" ) dir = "";

  ## Construct the url to confirm app
  url = dir + '/login.php';

  ##Send Request and Receive Response
  sndReq = http_get(item: url, port:http_port);
  rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);

  ##Confirm Application from Response
  if(rcvRes && "berta v" >< rcvRes && "Log in" >< rcvRes)
  {
    ## Upload file
    url = dir + '/upload.php';

    ## Confirm Upload
    ## extra check is not possible.
    if(http_vuln_check(port:http_port, url:url, pattern:"O*error"))
    {
      security_message(port:http_port);
      exit(0);
    }
  }
}

exit(99);