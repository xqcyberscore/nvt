###############################################################################
# OpenVAS Vulnerability Test
# $Id: rsh.nasl 11522 2018-09-21 13:34:05Z cfischer $
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
  script_version("$Revision: 11522 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-21 15:34:05 +0200 (Fri, 21 Sep 2018) $");
  script_tag(name:"creation_date", value:"2009-03-26 19:23:59 +0100 (Thu, 26 Mar 2009)");
  #Remark: NIST don't see "configuration issues" as software flaws so this CVSS has a value of 0.0.
  #However we still should report such a configuration issue with a criticality so this has been commented
  #out to avoid that the automatic CVSS score correction is setting the CVSS back to 0.0
  #  script_cve_id("CVE-1999-0651");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Check for rsh Service");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Useless services");
  script_dependencies("find_service1.nasl");
  script_require_ports("Services/rsh", "Services/unknown", 514);

  script_xref(name:"URL", value:"https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-1999-0651");

  script_tag(name:"solution", value:"Disable rsh and use ssh instead.");
  script_tag(name:"summary", value:"rsh Service is running at this Host.
  rsh (remote shell) is a command line computer program which can execute
  shell commands as another user, and on another computer across a computer
  network.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");
include("dump.inc");
include("http_func.inc"); # For make_list_unique

data = string( '0\0', "root", '\0', "root", '\0', 'id\0' ); #  Found in http://cpansearch.perl.org/src/ASLETT/Net-Rsh-0.05/Rsh.pm

ports = make_list( 514 );

unkn_ports = get_unknown_port_list( default:514 );
if( unkn_ports && is_array( unkn_ports ) )
  ports = make_list( ports, unkn_ports );

rsh_ports = get_kb_list( "Services/rsh" );
if( rsh_ports && is_array( rsh_ports ) )
  ports = make_list( ports, rsh_ports );

ports = make_list_unique( ports );

foreach port( ports ) {

  vuln = FALSE;

  if( ! get_port_state( port ) ) continue;
  if( ! soc = open_priv_sock_tcp( dport:port ) ) continue;

  send( socket:soc, data:data );
  buf = recv( socket:soc, length:8192 );
  close( soc );
  if( ! buf ) continue;

  # TODO/TBD: Add additional detection pattern?
  if( "Permission denied" >< buf ) {
    vuln = TRUE;
    report = "The rsh service is not allowing connections from this host.";
  } else if ( egrep( pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:bin2string( ddata:buf ) ) ) {
    vuln = TRUE;
    set_kb_item( name:"rsh/login_from", value:"root" );
    set_kb_item( name:"rsh/login_to", value:"root" );
    report = "The rsh service is misconfigured so it is allowing conntections without a password or with default root:root credentials.";
  } else if( "getnameinfo: Temporary failure in name resolution" >< buf ) {
    vuln = TRUE;
    report = "The rsh service currently has issues with name resolution and is not allowing connections from this host.";
  }

  if( vuln ) {
    set_kb_item( name:"rsh/active", value:TRUE );
    register_service( port:port, proto:"rsh" );
    security_message( port:port, data:report );
  }
}

if( vuln )
  exit( 0 );
else
  exit( 99 );