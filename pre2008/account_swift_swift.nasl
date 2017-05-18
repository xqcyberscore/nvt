###############################################################################
# OpenVAS Vulnerability Test
# $Id: account_swift_swift.nasl 6056 2017-05-02 09:02:50Z teissa $
#
# Default password 'swift' for account 'swift'
#
# Authors:
# Michel Arboi
#
# Copyright:
# Copyright (C) 2003 Michel Arboi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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

account = "swift";
password = "swift";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12116");
  script_version("$Revision: 6056 $");
  script_tag(name:"last_modification", value:"$Date: 2017-05-02 11:02:50 +0200 (Tue, 02 May 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Default password 'swift' for account 'swift'");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2003 Michel Arboi");
  script_dependencies("find_service.nasl", "ssh_detect.nasl");
  script_require_ports("Services/telnet", 23, "Services/ssh", 22);

  tag_summary = "The account 'swift' has the password 'swift'.";

  tag_solution = "Set a strong password for this account or disable it.";

  tag_impact = "An attacker may use it to gain further privileges on this system.";

  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"impact", value:tag_impact);

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("default_account.inc");

port = check_account( login:account, password:password );
if( port ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );
