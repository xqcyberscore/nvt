###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_eyeos_php_files_info_disc_vuln.nasl 7019 2017-08-29 11:51:27Z teissa $
#
# eyeOS '.php' Files Information Disclosure Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.902744");
  script_version("$Revision: 7019 $");
  script_tag(name:"last_modification", value:"$Date: 2017-08-29 13:51:27 +0200 (Tue, 29 Aug 2017) $");
  script_tag(name:"creation_date", value:"2011-09-30 15:58:03 +0200 (Fri, 30 Sep 2011)");
  script_cve_id("CVE-2011-3737");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("eyeOS '.php' Files Information Disclosure Vulnerability");
  script_xref(name : "URL" , value : "http://code.google.com/p/inspathx/source/browse/trunk/paths_vuln/eyeOS-2.2.0.0");
  script_xref(name : "URL" , value : "http://securityswebblog.blogspot.com/2011/09/vulnerability-summary-for-cve-2011-3737.html");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name : "impact" , value : "Successful exploitation will allow attacker to gain sensitive
  information.

  Impact Level: Application");
  script_tag(name : "affected" , value : "eyeOS version 2.2.0.0");
  script_tag(name : "insight" , value : "The flaw is due to error in certain '.php' files. A direct
  request to these files reveals the installation path in an error message.");
  script_tag(name : "solution" , value : "No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");
  script_tag(name : "summary" , value : "The host is running eyeOS and is prone to information disclosure
  vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Get the HTTP Port
port = get_http_port(default:80);

## Check Host Supports PHP
if(!can_host_php(port:port)) {
  exit(0);
}

foreach dir (make_list_unique("/eyeos", "/", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item:dir + "/index.php", port:port);

  ## Conform the application
  if("<title>Welcome to eyeos" >< rcvRes)
  {
    ## Construct the Attack Request
    url = dir + "/eyeos/apps/rmail/webmail/program/lib/Net/SMTP.php";

    ## Try attack and check the installation path in response.
    if(http_vuln_check(port:port, url:url, pattern:"<b>Fatal error</b>:  " +
                      "require_once() \[<a href='function.require'>function." +
                      "require</a>\]: Failed opening required 'PEAR.php'.*" +
                      "apps/rmail/webmail/program/lib/Net/SMTP.php"));
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);