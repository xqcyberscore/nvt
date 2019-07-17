###############################################################################
# OpenVAS Vulnerability Test
#
# Cisco ASA Software Information Disclosure Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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

CPE = "cpe:/a:cisco:asa";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105194");
  script_bugtraq_id(70230);
  script_cve_id("CVE-2014-3398");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_version("2019-07-05T09:54:18+0000");

  script_name("Cisco ASA Software Information Disclosure Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70230");

  script_tag(name:"impact", value:"An attacker can leverage this issue to obtain sensitive information
that may aid in further attacks.");

  script_tag(name:"vuldetect", value:"Try to access /CSCOSSLC/config-auth and check the response");
  script_tag(name:"solution", value:"Updates are available.");
  script_tag(name:"summary", value:"Cisco ASA Software is prone to an information-disclosure
vulnerability.");
  script_tag(name:"insight", value:"This issue is being tracked by Cisco bug ID CSCuq65542.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2019-07-05 09:54:18 +0000 (Fri, 05 Jul 2019)");
  script_tag(name:"creation_date", value:"2015-02-03 11:59:05 +0100 (Tue, 03 Feb 2015)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_asa_detect.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("cisco_asa/webvpn/installed");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");


if( ! port = get_app_port( cpe:CPE, service: "www" ) ) exit( 0 );

url = '/CSCOSSLC/config-auth';
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "VPN Server internal error" >!< buf ) exit( 0 );

if( eregmatch( pattern:'<version who.*>([0-9.()]+)</version>', string:buf) )
{
  security_message( port:port );
  exit( 0 );
}

exit( 99 );
