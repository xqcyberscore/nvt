###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ajaxportal_file_inc_vuln.nasl 4865 2016-12-28 16:16:43Z teissa $
#
# AjaxPortal 'di.php' File Inclusion Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800817");
  script_version("$Revision: 4865 $");
  script_tag(name:"last_modification", value:"$Date: 2016-12-28 17:16:43 +0100 (Wed, 28 Dec 2016) $");
  script_tag(name:"creation_date", value:"2009-07-03 15:23:01 +0200 (Fri, 03 Jul 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-2262");
  script_name("AjaxPortal 'di.php' File Inclusion Vulnerability");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/504618/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ajaxportal_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name : "impact" , value : "Successful exploitation will let the remote attacker to execute
  arbitrary PHP code via a URL in the pathtoserverdata parameter.

  Impact Level: Application");
  script_tag(name : "affected" , value : "MyioSoft, AjaxPortal version 3.0");
  script_tag(name : "insight" , value : "The flaw is due to error in the 'pathtoserverdata' parameter in
  install/di.php and it can exploited to cause PHP remote file inclusion.");
  script_tag(name : "solution" , value : "No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");
  script_tag(name : "summary" , value : "The host is running AjaxPortal and is prone to File Inclusion
  vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

ajaxPort = get_http_port(default:80);

## Check the php support
if(!can_host_php(port:ajaxPort)){
  exit(0);
}

foreach dir (make_list_unique("/", "/ajaxportal", "/portal", cgi_dirs(port:ajaxPort)))
{

  if(dir == "/") dir = "";

  sndReq = http_get(item:dir + "/install/index.php", port:ajaxPort);
  rcvRes = http_keepalive_send_recv(data:sndReq, port:ajaxPort);

  if(rcvRes =~ "MyioSoft EasyInstaller" &&
     egrep(pattern:"^HTTP/.* 200 OK", string:rcvRes))
  {
    ajaxVer = get_kb_item("www/" + ajaxPort + "/AjaxPortal");
    ajaxVer = eregmatch(pattern:"^(.+) under (/.*)$", string:ajaxVer);
    if(ajaxVer[1] != NULL)
    {
      if(version_is_equal(version:ajaxVer[1], test_version:"3.0"))
      {
         security_message(port:ajaxPort);
         exit(0);
      }
    }
  }
}

exit(99);