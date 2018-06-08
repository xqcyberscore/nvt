###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ssh_authentication_bypass_vuln.nasl 10121 2018-06-07 12:44:05Z cfischer $
#
# SSH SSH-1 Protocol Authentication Bypass Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801993");
  script_version("$Revision: 10121 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-07 14:44:05 +0200 (Thu, 07 Jun 2018) $");
  script_tag(name:"creation_date", value:"2011-10-14 14:22:41 +0200 (Fri, 14 Oct 2011)");
  script_cve_id("CVE-2001-1473");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("SSH SSH-1 Protocol Authentication Bypass Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("ssh_detect.nasl", "ssh_proto_version.nasl");
  script_require_ports("Services/ssh", 22);

  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/684820");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/6603");

  script_tag(name:"impact", value:"Successful exploitation could allows remote attackers to bypass security
  restrictions and to obtain a client's public host key during a connection
  attempt and use it to open and authenticate an SSH session to another
  server with the same access.

  Impact Level: Application");

  script_tag(name:"affected", value:"SSH Protocol Version SSH-1");

  script_tag(name:"insight", value:"The flaw is due to an error in the SSH-1 protocol authentication
  process when encryption is disabled, which allows client authentication to
  be forwarded by a malicious server to another server.");

  script_tag(name:"solution", value:"Upgrade to SSH SSH-2,
  For updates refer to http://www.openssh.com/");

  script_tag(name:"summary", value:"The host is running SSH and is prone to authentication
  bypass vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ssh_func.inc");

port = get_ssh_port( default:22 );
banner = get_ssh_server_banner( port:port );
if( ! banner ) exit( 0 );

dnnVer = get_kb_item( "SSH/supportedversions/" + port );
if( ( dnnVer =~ "'1\..*" ) && ! ( dnnVer =~ "'[2-9]\..*" ) ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );