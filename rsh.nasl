###############################################################################
# OpenVAS Vulnerability Test
# $Id: rsh.nasl 4378 2016-10-28 09:01:50Z cfi $
#
# Check for rsh Service
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100080");
  script_version("$Revision: 4378 $");
  script_tag(name:"last_modification", value:"$Date: 2016-10-28 11:01:50 +0200 (Fri, 28 Oct 2016) $");
  script_tag(name:"creation_date", value:"2009-03-26 19:23:59 +0100 (Thu, 26 Mar 2009)");
  #Remark: NIST don't see "configuration issues" as software flaws so this CVSS has a value of 0.0.
  #However we still should report such a configuration issue with a criticality so this has been commented
  #out to avoid that the automatic CVSS score correction is setting the CVSS back to 0.0
  #script_cve_id("CVE-1999-0651");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Check for rsh Service");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Useless services");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/unknown", 514);

  script_xref(name:"URL", value:"https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-1999-0651");

  tag_solution = "Disable rsh and use ssh instead.";

  tag_summary = "rsh Service is running at this Host.
  rsh (remote shell) is a command line computer program which can execute
  shell commands as another user, and on another computer across a computer
  network.";

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");
include("dump.inc");

data = string( '0\0', "root", '\0', "root", '\0', 'id\0' ); #  Found in http://cpansearch.perl.org/src/ASLETT/Net-Rsh-0.05/Rsh.pm

port = get_unknown_port( default:514 );

soc = open_priv_sock_tcp( dport:port );
if( ! soc ) exit( 0 );

send( socket:soc, data:data );
buf = recv( socket:soc, length:8192 );
close( soc );
if( isnull( buf ) ) exit( 0 );

# TODO/TBD: Add additional detection pattern?
if( "Permission denied" >< buf ) {
  vuln = TRUE;
  report = "The rsh Service is not allowing connections from this host.";
} else if ( egrep( pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:bin2string( ddata:buf ) ) ) {
  vuln = TRUE;
  set_kb_item( name:"rsh/login_from", value:"root" );
  set_kb_item( name:"rsh/login_to", value:"root" );
  report = "The rsh Service is misconfigured so it is allowing conntections without a password or with default root:root credentials.";
}

if( vuln ) {
  set_kb_item( name:"rsh/active", value:TRUE );
  register_service( port:port, proto:"rsh" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
