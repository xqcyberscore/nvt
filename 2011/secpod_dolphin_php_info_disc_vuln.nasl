###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_dolphin_php_info_disc_vuln.nasl 7052 2017-09-04 11:50:51Z teissa $
#
# Dolphin '.php' Files Information Disclosure Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.902735");
  script_version("$Revision: 7052 $");
  script_tag(name:"last_modification", value:"$Date: 2017-09-04 13:50:51 +0200 (Mon, 04 Sep 2017) $");
  script_tag(name:"creation_date", value:"2011-09-30 15:58:03 +0200 (Fri, 30 Sep 2011)");
  script_cve_id("CVE-2011-3728");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Dolphin '.php' Files Information Disclosure Vulnerability");
  script_xref(name : "URL" , value : "http://code.google.com/p/inspathx/source/browse/trunk/paths_vuln/Dolphin-7.0.4");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name : "impact" , value : "Successful exploitation will allow attacker to gain sensitive
  information.

  Impact Level: Application");
  script_tag(name : "affected" , value : "Dolphin version 7.0.4");
  script_tag(name : "insight" , value : "The flaw is due to error in certain '.php' files. A direct
  request to these files reveals the installation path in an error message.");
  script_tag(name : "solution" , value : "No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");
  script_tag(name : "summary" , value : "The host is running Dolphin and is prone to information
  disclosure vulnerability.");

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

  ## Check for the possible paths
  rcvRes = http_get_cache(item: path + "/index.php", port:dolPort);

  ##  Confirm application
  if("<title>dolphin</title>" >< rcvRes)
  {
    ## Construct the exploit request
    url = path + "/xmlrpc/BxDolXMLRPCProfileView.php";

    ## Try attack and check the installation path in response.
    if(http_vuln_check(port:dolPort, url:url, pattern:"<b>Fatal error</b>:  " +
       "require_once\(\) \[<a href='function.require'>function.require</a>\]:"+
       " Failed opening required.*xmlrpc/BxDolXMLRPCProfileView.php")){
      security_message(port:dolPort);
      exit(0);
    }
  }
}

exit(99);