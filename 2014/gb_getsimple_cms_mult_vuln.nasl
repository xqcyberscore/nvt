###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_getsimple_cms_mult_vuln.nasl 3522 2016-06-15 12:39:54Z benallard $
#
# GetSimple CMS Multiple Vulnerabilities
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.804225");
  script_version("$Revision: 3522 $");
  script_cve_id("CVE-2012-6621", "CVE-2013-7243");
  script_bugtraq_id(53501);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2016-06-15 14:39:54 +0200 (Wed, 15 Jun 2016) $");
  script_tag(name:"creation_date", value:"2014-01-21 17:46:37 +0530 (Tue, 21 Jan 2014)");
  script_name("GetSimple CMS Multiple Vulnerabilities");

  script_tag(name : "summary" , value : "This host is running GetSimple CMS and is prone to multiple vulnerabilities.");
  script_tag(name : "vuldetect" , value : "Send a crafted string via HTTP GET request and check whether it
  is able to inject HTML code.");
  script_tag(name : "insight" , value : "Flaw exists in upload.php, theme.php, pages.php, settings.php and index.php
  scripts, which fail to properly sanitize user-supplied input to 'path',
  'err', 'error' and 'success' parameter and 'Custom Permalink Structure',
  'Display name', 'Email Address' fields");
  script_tag(name : "impact" , value : "Successful exploitation will allow remote attackers to inject HTML code or
  steal the victim's cookie-based authentication credentials.

  Impact Level: Application");
  script_tag(name : "affected" , value : "GetSimple CMS 3.1, 3.1.2, 3.2.3, Other versions may also be affected.");
  script_tag(name : "solution" , value : "No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/75534");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/75535");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/124711");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/112643");
  script_summary("Check if GetSimple CMS is vulnerable to HTML injection");
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
http_port = "";
req = "";
res = "";
url = "";

## Get HTTP Port
http_port = get_http_port(default:80);

## Check Host Supports PHP
if(!can_host_php(port:http_port)){
  exit(0);
}

## Iterate over possible paths
foreach dir (make_list_unique("/", "/cms", "/simplecms", "/getsimplecms", cgi_dirs(port:http_port)))
{

  if(dir == "/") dir = "";

  req = http_get(item:string(dir, "/index.php"),  port:http_port);
  res = http_keepalive_send_recv(port:http_port, data:req);

  ## confirm the Application
  if(res &&  "Welcome to GetSimple!" >< res && "Powered by  GetSimple" >< res)
  {
    ## Construct Attack Request
    url = dir + '/admin/index.php?success=>"<iframe%20src=http://www.example.com>';

    ## Check the response to confirm vulnerability
    if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
       pattern:"http://www.example.com"))
    {
      security_message(port:http_port);
      exit(0);
    }
  }
}

exit(99);