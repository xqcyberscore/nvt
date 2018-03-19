###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_iis6_97127.nasl 9128 2018-03-19 07:45:38Z cfischer $
#
# Microsoft Internet Information Services  Buffer Overflow Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

CPE = "cpe:/a:microsoft:iis";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140228");
  script_bugtraq_id(97127);
  script_cve_id("CVE-2017-7269");
  script_version("$Revision: 9128 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-03-19 08:45:38 +0100 (Mon, 19 Mar 2018) $");
  script_tag(name:"creation_date", value:"2017-03-30 17:46:17 +0200 (Thu, 30 Mar 2017)");
  script_name("Microsoft Internet Information Services  Buffer Overflow Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("secpod_ms_iis_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("IIS/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97127");
  script_xref(name:"URL", value:"http://www.microsoft.com");
  script_xref(name:"URL", value:"https://github.com/edwardz246003/IIS_exploit");

  script_tag(name:"impact", value:"Attackers can exploit this issue to execute arbitrary code in the context
  of the affected application. Failed exploit attempts will result in denial-of-service conditions.");

  script_tag(name:"vuldetect", value:"Check the version and if WebDAV is enabled.");

  script_tag(name:"solution", value:"Windows 2003 is EOL. Please update to a supported Operating
  System version.");

  script_tag(name:"summary", value:"Microsoft Internet Information Services is prone to a buffer overflow
  vulnerability because it fails to adequately bounds-check user-supplied data before copying it to an
  insufficiently sized memory buffer.");

  script_tag(name:"affected", value:"Microsoft Internet Information Services 6.0 running on Microsoft
  Windows Server 2003 R2 is vulnerable; other versions may also be affected.");

  script_tag(name:"solution_type", value:"NoneAvailable");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( vers != "6.0" ) exit( 99 );

host = http_host_name(  port:port );

req  = 'OPTIONS / HTTP/1.1\r\n';
req += 'Host: ' + host + '\r\n';
req += 'User-Agent: ' + OPENVAS_HTTP_USER_AGENT + '\r\n';
req += '\r\n';

buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "Allow:" >!< buf || "MS-Author-Via: DAV" >!< buf ) exit( 99 );

line = egrep( pattern:'^Allow:', string:buf );

if( "PROPFIND" >< line ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );
