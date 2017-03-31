###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sitecorecms_xss_vuln.nasl 3499 2016-06-13 13:18:43Z benallard $
#
# Sitecore_CMS XSS Vulnerabilities
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.805497");
  script_version("$Revision: 3499 $");
  script_cve_id("CVE-2014-100004");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2016-06-13 15:18:43 +0200 (Mon, 13 Jun 2016) $");
  script_tag(name:"creation_date", value:"2015-03-20 10:14:06 +0530 (Fri, 20 Mar 2015)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("Sitecore_CMS XSS Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with Sitecore CMS
  and is prone to cross site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Flaw is due to the default.aspx script does
  not validate input to the 'xmlcontrol' parameter before returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow a
  context-dependent attacker to create a specially crafted request that would
  execute arbitrary script code in a user's browser session within the trust
  relationship between their browser and the server.

  Impact Level: Application");

  script_tag(name:"affected", value:"Sitecore CMS before 7.0 Update-4 (rev. 140120).");

  script_tag(name: "solution" , value:"Upgrade to Sitecore CMS before 7.0
  Update-4 (rev. 140120).
  For updates refer to http://www.sitecore.net/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "http://www.idappcom.com/db/?9066");
  script_xref(name : "URL" , value : "http://sitecorekh.blogspot.dk/2014/01/sitecore-releases-70-update-4-rev-140120.html");

  script_summary("Check if Sitecore CMS is prone to xss");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

# Variable Initialization
http_port = "";
sndReq = "";
rcvRes = "";

# Get HTTP Port
http_port = get_http_port(default:80);
if (!http_port) {
  http_port = 80;
}

# Check the port status
if(!get_port_state(http_port)){
  exit(0);
}

# Iterate over possible paths
foreach dir (make_list_unique("/", "/sitecore", "/sitecore_cms", cgi_dirs()))
{

  if( dir == "/" ) dir = "";

  # Construct GET Request
  sndReq = http_get(item:dir + "/login",  port:http_port);
  rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);

  ##Confirm Application
  if(rcvRes && "Welcome to Sitecore" >< rcvRes)
  {
    ##Construct Attack Request
    url = dir + "/login?xmlcontrol=body%20onload=alert%28document.cookie%29";

    ## Try attack and check the response to confirm vulnerability
    if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
       pattern:"alert\(document.cookie\)"))
    {
      report = report_vuln_url( port:http_port, url:url );
      security_message(port:http_port, data:report);
      exit(0);
    }
  }
}

exit(99);
