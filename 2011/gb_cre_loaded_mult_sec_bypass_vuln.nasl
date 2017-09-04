###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cre_loaded_mult_sec_bypass_vuln.nasl 7024 2017-08-30 11:51:43Z teissa $
#
# CRE Loaded Multiple Security Bypass Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802104");
  script_version("$Revision: 7024 $");
  script_tag(name:"last_modification", value:"$Date: 2017-08-30 13:51:43 +0200 (Wed, 30 Aug 2017) $");
  script_tag(name:"creation_date", value:"2011-06-20 15:22:27 +0200 (Mon, 20 Jun 2011)");
  script_cve_id("CVE-2009-5076", "CVE-2009-5077");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("CRE Loaded Multiple Security Bypass Vulnerabilities");
  script_xref(name : "URL" , value : "http://hosting-4-creloaded.com/node/116");
  script_xref(name : "URL" , value : "https://www.creloaded.com/fdm_file_detail.php?file_id=191");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name : "impact" , value : "Successful exploitation will allow attacker to bypass authentication and
  gain administrator privileges.

  Impact Level: Application");
  script_tag(name : "affected" , value : "CRE Loaded version before 6.4.0");
  script_tag(name : "insight" , value : "The flaws are due to
  - An error when handling 'PHP_SELF' variable, by includes/application_top.php
    and admin/includes/application_top.php.
  - Request, with 'login.php' or 'password_forgotten.php' appended as the
    'PATH_INFO', which bypasses a check that uses 'PHP_SELF', which is not
    properly handled by includes/application_top.php and
    admin/includes/application_top.php.");
  script_tag(name : "solution" , value : "Upgrade to CRE Loaded version 6.4.0 or later
  For updates refer to http://www.creloaded.com/");
  script_tag(name : "summary" , value : "The host is running CRE Loaded and is prone to Security bypass
  vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);

## Check Host Supports PHP
if(!can_host_php(port:port)) {
  exit(0);
}

foreach dir(make_list_unique("/cre", "/cre-loaded", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  ## Send and Receive the response
  res = http_get_cache(item: dir + "/index.php", port:port);

  ## Confirm the application
  if('<title>CRE Loaded' >< res)
  {
    ## Get the version
    ver = eregmatch(pattern:"v([0-9.]+)" , string:res);
    if (ver != NULL)
    {
      ## Check the version less than 6.4.0
      if(version_is_less(version:ver, test_version:"6.4.0")){
        security_message(port:port);
      }
    }
  }
}

exit(99);