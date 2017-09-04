###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_wsn_software_dir_php_files_info_disc_vuln.nasl 7015 2017-08-28 11:51:24Z teissa $
#
# WSN Software Directory '.php' Files Information Disclosure Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.902743");
  script_version("$Revision: 7015 $");
  script_tag(name:"last_modification", value:"$Date: 2017-08-28 13:51:24 +0200 (Mon, 28 Aug 2017) $");
  script_tag(name:"creation_date", value:"2011-09-30 15:58:03 +0200 (Fri, 30 Sep 2011)");
  script_cve_id("CVE-2011-3820");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("WSN Software Directory '.php' Files Information Disclosure Vulnerability");
  script_xref(name : "URL" , value : "http://code.google.com/p/inspathx/source/browse/trunk/paths_vuln/WSN_Software_6.0.6");
  script_xref(name : "URL" , value : "http://itsecuritysolutions.org/2010-11-21_WSN_Software_6.0.6_multiple_vulnerabilities/");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name : "impact" , value : "Successful exploitation will allow attacker to gain sensitive
  information.

  Impact Level: Application");
  script_tag(name : "affected" , value : "WSN Software Directory version 6.0.6");
  script_tag(name : "insight" , value : "The flaw is due to error in certain '.php' files. A direct
  request to these files reveals the installation path in an error message.");
  script_tag(name : "solution" , value : "No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.

  A workaround is to Disable php error_display off.");
  script_tag(name : "summary" , value : "The host is running WSN Software Directory and is prone to
  information disclosure vulnerability.");

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

foreach dir (make_list_unique("/wsnsd", "/", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  ## Send and Receive the response
  rcvRes = http_get_cache(item: dir + "/index.php", port:port);

  ## Conform the application
  if("<title>Software Directory </title>" >< rcvRes)
  {
    ## Construct the Attack Request
    url = dir + "/includes/prestart.php";

    ## Try attack and check the installation path in response.
    if(http_vuln_check(port:port, url:url, pattern:"<b>Fatal error</b>:  " +
                  "require_once() \[<a href='function.require'>function." +
                  "require</a>\]: Failed opening required 'scriptinfo.php'.*" +
                  "includes/prestart.php"));
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);