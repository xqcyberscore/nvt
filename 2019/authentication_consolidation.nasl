###############################################################################
# OpenVAS Vulnerability Test
# $Id: authentication_consolidation.nasl 1.0 2019-02-07 16:20:00Z $
#
# Check that SMB, WMI and remote registry were accessible on a windows host and that SSH and a shell are available on nix hosts.
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.300031");
  script_version("$Revision: 1.0 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-11 16:23:53 +0200 (Tue, 11 Sep 2018) $");
  script_name('Authentication Consolidation');
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2018 XQ Cyber");
  script_family("General");
  script_dependencies("2018/gb_win_lsc_authentication_info.nasl", "gather-package-list.nasl");

  exit(0);
}

include("smb_nt.inc");
include("ssh_func.inc");

report = "";
full_smb_auth = TRUE;
full_ssh_auth = TRUE;

# SMB/WMI checks
if(get_kb_item("login/SMB/success")){
	report += "SMB login successful\n";
	full_smb_auth = full_smb_auth && TRUE;
}else{
	report += "SMB login unsuccessful\n";
	full_smb_auth = FALSE;
}

if(get_kb_item("WMI/access_successful")){
	report += "WMI access successful\n";
	full_smb_auth = full_smb_auth && TRUE;
}else{
	report += "WMI access unsuccessful\n";
	full_smb_auth = FALSE;
}

if(get_kb_item("SMB/registry_access")){
	report += "Registry access successful\n";
	full_smb_auth = full_smb_auth && TRUE;
}else{
	report += "Registry access unsuccessful\n";
	full_smb_auth = FALSE;
}


buf = "";
if(!get_kb_item( "win/lsc/disable_win_cmd_exec" )){
	username = kb_smb_login();
    domain  = kb_smb_domain();

    if (domain){
      username = domain + '/' + username;
    }
    password = kb_smb_password();

	buf = win_cmd_exec(cmd:'powershell.exe -Command whoami /GROUPS', password:password, username:username);
}

if("BUILTIN\Administrators" >< buf){
	report += "Admin privileges detected\n";
	full_smb_auth = full_smb_auth && TRUE;
}else{
	report += "Admin privileges not detected\n";
	full_smb_auth = FALSE;
}


# ssh checks
if(get_kb_item("login/SSH/success")){
	report += "SSH access successful\n";
	full_ssh_auth = full_ssh_auth && TRUE;
}else{
	report += "SSH access unsuccessful\n";
	full_ssh_auth = FALSE;
}

if(get_kb_item("login/SSH/success") && !get_kb_item("ssh/no_linux_shell")){
	report += "SSH shell available\n";
	full_ssh_auth = full_ssh_auth && TRUE;
}else{
	report += "SSH shell unavailable\n";
	full_ssh_auth = FALSE;
}

buf = "";
if(get_kb_item("login/SSH/success") && !get_kb_item("ssh/no_linux_shell")){

	# Check if port for us is known
	port = get_preference( "auth_port_ssh" );
	if( ! port )
		port = get_kb_item( "Services/ssh" );
    if( ! port )
		port = 22;

	sock_g = ssh_login_or_reuse_connection();
	if (! sock_g)
		exit(1);

	host_ip = get_host_ip();
	passwd = kb_ssh_password();

	cmd = string("echo '" + passwd + "'|sudo -S 2>/dev/null whoami");

	buf = ssh_cmd_exec(cmd: cmd);
	ssh_close_connection();
}

if("root" == buf){
	report += "SSH sudo available\n";
	full_ssh_auth = full_ssh_auth && TRUE;
}else{
	report += "SSH sudo unavailable\n";
	full_ssh_auth = FALSE;
}

if(full_smb_auth || full_ssh_auth){
	report = "Fully Authed\n" + report;
}

log_message(data:report);

exit(0);
