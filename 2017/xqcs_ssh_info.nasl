###############################################################################
# OpenVAS Vulnerability Test
# $Id: xqcs_ssh_info.nasl 1.0 2017-11-21 12:06:44Z $
#
# Linux System Info
#
# Authors:
# Daniel Craig <daniel.craig@xqcyber.com>
#
# Copyright:
# Copyright (c) 2017 XQ Digital Resilience Limited
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.300000");
  script_version("$Revision: 1.0 $");
  script_name("Linux System Info");
  script_tag(name:"summary", value:"Fetch system info from linux hosts");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 XQ Digital Resilience Limited.");
  script_family("General");

  script_dependencies("gather-package-list.nasl", "ssh_authorization_init.nasl", "global_settings.nasl");
  script_mandatory_keys("Secret/SSH/login", "Host/uname");
  exit(0);
}

include("misc_func.inc");
include("ssh_func.inc");

if( get_kb_item( "global_settings/authenticated_scans_disabled" ) ) exit( 0 ); 

# Check if port for us is known
port = get_preference( "auth_port_ssh" );
if( ! port )
  port = get_kb_item( "Services/ssh" );

uname = get_kb_item("Host/uname");
if ("Linux" >!< uname){
  exit(0);
}

sock_g = ssh_login_or_reuse_connection();
if (! sock_g)
  exit(1);

host_ip = get_host_ip();

cmd = string("IFCONFIG=$(ifconfig -a|grep -B 1 "+ host_ip +");touch /tmp/me;echo -n 'uname=';uname -a;echo -n 'hostname=';hostname -f;echo -n 'mac=';echo $IFCONFIG|grep HWaddr|cut -d' ' -f5");

buf = ssh_cmd_exec(cmd: cmd);
ssh_close_connection();
log_message(port:port, data:buf);
exit(0);
