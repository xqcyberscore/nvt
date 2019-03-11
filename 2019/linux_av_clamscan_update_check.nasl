###############################################################################
# OpenVAS Vulnerability Test
# $Id: linux_av_clamscan_update_check.nasl 1.0 2019-01-28 14:20:00Z $
#
# Check clamscan anti-malware product update version and update time.
#
# Authors:
# Stephen Penn <stephen.penn@xqcyber.com>
#
# Copyright:
# Copyright (c) 2019 XQ Digital Resilience Limited
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.300033");
  script_version("$Revision: 1.0 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-12 16:14:00 +0000 (Tue, 12 Feb 2019) $");
  script_name('clamscan version check');
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2019 XQ Cyber");
  script_family("Compliance");
  script_dependencies("2019/linux_anti_malware_consolidation.nasl", "ssh_authorization.nasl");
  script_mandatory_keys("login/SSH/success", "AV/CLAMSCAN");

  exit(0);
}

include("misc_func.inc");
include("ssh_func.inc");

if( get_kb_item( "global_settings/authenticated_scans_disabled" ) ) exit( 0 );

# Check if port for us is known
port = get_preference( "auth_port_ssh" );
if( ! port )
  port = get_kb_item( "Services/ssh" );
if( ! port )
  port = 22;

sock_g = ssh_login_or_reuse_connection();
if (! sock_g)
  exit(1);

which = ssh_cmd_exec(cmd: string('which clamscan'));

ssh_close_connection();

if ( which == "" ) {
	log_message(data:"clamscan binary not found");
	exit(1);
}

sock_g = ssh_login_or_reuse_connection();

if (! sock_g)
  exit(1);
  cmd = string('[ $(host -t txt current.cvd.clamav.net | cut -d ":" -f3) == $(' + which +' -V | cut -d "/" -f2) ] && echo "Clamscan definitions up to date" || echo "Clamscan definitions out of date"');
buf = ssh_cmd_exec(cmd:cmd);

ssh_close_connection();
log_message(port:port, data:buf);
exit(0);
