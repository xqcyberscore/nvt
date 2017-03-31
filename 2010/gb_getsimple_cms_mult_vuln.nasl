##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_getsimple_cms_mult_vuln.nasl 5306 2017-02-16 09:00:16Z teissa $
#
# GetSimple CMS Multiple Vulnerabilities.
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801410");
  script_version("$Revision: 5306 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-16 10:00:16 +0100 (Thu, 16 Feb 2017) $");
  script_tag(name:"creation_date", value:"2010-07-26 16:14:51 +0200 (Mon, 26 Jul 2010)");
  script_bugtraq_id(41697);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("GetSimple CMS Multiple Vulnerabilities");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/40428");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2010/May/234");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name : "insight" , value : "The flaws are due to, input passed to various scripts via various
  parameters are not properly sanitized before being returned to the user.");
  script_tag(name : "solution" , value : "Upgrade to version 2.03 or later,
  For updates refer to http://get-simple.info/download");
  script_tag(name : "summary" , value : "This host is running GetSimple CMS and is prone to multiple
  vulnerabilities.");
  script_tag(name : "impact" , value : "Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in a user's browser session in context of an affected site.

  Impact Level: Application");
  script_tag(name : "affected" , value : "GetSimple CMS version 2.01");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

## Get HTTP Port
cmsPort = get_http_port(default:80);

## Check the php support
if(!can_host_php(port:cmsPort)){
  exit(0);
}

foreach dir (make_list_unique("/GetSimple", "/getsimple" , cgi_dirs(port:cmsPort)))
{

  if(dir == "/") dir = "";

  ## Send and Receive request
  rcvRes = http_get_cache(item: dir + "/index.php", port:cmsPort);

  ## Confirm application is GetSimple CMS
  if(">Powered by GetSimple<" >< rcvRes)
  {
    ## Grep the version
    cmsVer = eregmatch(pattern:"> Version ([0-9.]+)<" , string:rcvRes);
    if(cmsVer[1] != NULL)
    {
      ## Check for the GetSimple CMS version equal 2.01
      if(version_is_equal(version:cmsVer[1], test_version:"2.01")){
        security_message(port:cmsPort);
        exit(0);
      }
    }
  }
}

exit(99);