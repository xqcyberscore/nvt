###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_finger_remote_info_disc_vuln.nasl 4378 2016-10-28 09:01:50Z cfi $
#
# Finger Service Remote Information Disclosure Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802236");
  script_version("$Revision: 4378 $");
  script_tag(name:"last_modification", value:"$Date: 2016-10-28 11:01:50 +0200 (Fri, 28 Oct 2016) $");
  script_tag(name:"creation_date", value:"2011-08-12 14:44:50 +0200 (Fri, 12 Aug 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  #Remark: NIST don't see "configuration issues" as software flaws so this CVSS has a value of 0.0.
  #However we still should report such a configuration issue with a criticality so this has been commented
  #out to avoid that the automatic CVSS score correction is setting the CVSS back to 0.0
  # script_cve_id("CVE-1999-0612");
  script_name("Finger Service Remote Information Disclosure Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Finger abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/finger", 79);

  script_xref(name:"URL", value:"https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-1999-0612");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/46");
  script_xref(name:"URL", value:"http://www.iss.net/security_center/reference/vuln/finger-running.htm");

  tag_impact = "Successful exploitation will allow attacker to obtain sensitive information
  that could aid in further attacks.

  Impact Level: Application";

  tag_affected = "GNU Finger.";

  tag_insight = "The flaw exists due to finger service exposes valid user information to any
  entity on the network.";

  tag_solution = "Disable finger service, or install a finger service or daemon that
  limits the type of information provided.";

  tag_summary = "This host is running Finger service and is prone to information
  disclosure vulnerability.";

  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);
  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"solution", value:tag_solution);

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

port = get_kb_item( "Services/finger" );
if( ! port ) port = 79;

if( ! get_port_state( port ) ) exit( 0 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

## Confirm Finger
banner = recv( socket:soc, length:2048, timeout:5 );
if( banner ) exit( 0 ); #TDB: Really exit here if a banner was received?

## Send And Receive The Response
send( socket:soc, data:string( "root\r\n" ) );
res = recv( socket:soc, length:2048 );
close( soc );

## Confirm Vulnerability
if( "Login" >< res || "User" >< res || "logged" >< res ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );
