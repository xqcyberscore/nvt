###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_aflog_cookie_auth_bypass_vuln.nasl 5657 2017-03-21 11:08:08Z cfi $
#
# aflog Cookie-Based Authentication Bypass Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800304");
  script_version("$Revision: 5657 $");
  script_tag(name:"last_modification", value:"$Date: 2017-03-21 12:08:08 +0100 (Tue, 21 Mar 2017) $");
  script_tag(name:"creation_date", value:"2008-11-11 09:00:11 +0100 (Tue, 11 Nov 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-4784");
  script_bugtraq_id(31894);
  script_name("aflog Cookie-Based Authentication Bypass Vulnerability");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/6818");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name : "impact" , value : "Exploitation will allow an attacker to gain administrative access and bypass
  authentication.

  Impact Level: System");
  script_tag(name : "affected" , value : "aflog versions 1.01 and prior on all running platform");
  script_tag(name : "insight" , value : "The flaw is due to inadequacy in verifying user-supplied input used
  for cookie-based authentication by setting the aflog_auth_a cookie to
  'A' or 'O' in edit_delete.php, edit_cat.php, edit_lock.php, and edit_form.php.");
  script_tag(name : "solution" , value : "No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.
  For updates refer to http://www.aflog.org/");
  script_tag(name : "summary" , value : "This host is running aflog and is prone to cookie-based authentication
  bypass vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

## Check the php support
if(!can_host_php(port:port)){
  exit(0);
}

foreach path (make_list_unique("/aflog", cgi_dirs(port:port)))
{

  if(path == "/") path = "";

  sndReq = http_get(item: path + "/Readme.txt", port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

  if(egrep(pattern:"Aflog v1.01", string:rcvRes) &&
     egrep(pattern:"^HTTP/.* 200 OK", string:rcvRes))
  {
    security_message(port:port);
    exit(0);
  }
}

exit(99);