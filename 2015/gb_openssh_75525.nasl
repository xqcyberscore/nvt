###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssh_75525.nasl 2676 2016-02-17 09:05:41Z benallard $
#
# OpenSSH 'x11_open_helper()' Function Security Bypass Vulnerability
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

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.105317");
 script_bugtraq_id(75525);
 script_cve_id("CVE-2015-5352");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_version ("$Revision: 2676 $");

 script_name("OpenSSH 'x11_open_helper()' Function Security Bypass Vulnerability");

 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75525");
 script_xref(name:"URL", value:"http://www.openssh.com");

 script_tag(name: "impact" , value:"An attacker can exploit this issue to bypass certain security
restrictions and perform unauthorized actions. This may lead to further attacks");

 script_tag(name: "vuldetect" , value:"Check the version from ssh-banner.");
 script_tag(name: "solution" , value:"Update to 6.9 or newer.");
 script_tag(name: "summary" , value:"OpenSSH is prone to a security-bypass vulnerability.

This NVT has been replaced by NVT gb_openssh_security_bypass_vuln.nasl (1.3.6.1.4.1.25623.1.0.806049)");
 script_tag(name: "affected" , value:"OpenSSH < 6.9");

 script_tag(name:"solution_type", value: "VendorFix");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");

 script_tag(name:"last_modification", value:"$Date: 2016-02-17 10:05:41 +0100 (Wed, 17 Feb 2016) $");
 script_tag(name:"creation_date", value:"2015-07-09 10:06:32 +0200 (Thu, 09 Jul 2015)");
 script_summary("Check the version from ssh-banner");
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
 script_dependencies("ssh_detect.nasl");
 script_require_ports("Services/ssh", 22);


 script_tag(name:"deprecated", value:TRUE); 

 exit(0);
}

# This NVT has been replaced by NVT gb_openssh_security_bypass_vuln.nasl (1.3.6.1.4.1.25623.1.0.806049)
exit(66);

include("version_func.inc");

port = get_kb_item("Services/ssh");
if( ! port ) exit( 0 );;

if( ! get_port_state( port ) ) exit( 0 );

banner = tolower( get_kb_item( "SSH/banner/" + port ) );
if( ! banner || "openssh" >!< banner ) exit(0);

ver = eregmatch( pattern:"openssh[-_]([0-9][-._0-9a-z]+)", string:banner );

if( isnull(ver[1] ) ) exit( 0 );

if( version_is_less( version:ver[1], test_version:"6.9" ) )
{
  report = 'Installed version: ' + ver[1] + '\n' +
           'Fixed version:     6.9';

  security_message( port:port, data:report );
  exit(0);
}

exit(0);
