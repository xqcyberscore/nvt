###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bash_shellshock_credential_cmd_exec_vuln_02.nasl 3517 2016-06-14 12:46:45Z benallard $
#
# GNU Bash Environment Variable Handling Shell RCE Vulnerability (LSC) - 02
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802082");
  script_version("$Revision: 3517 $");
  script_cve_id("CVE-2014-7169");
  script_bugtraq_id(70137);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2016-06-14 14:46:45 +0200 (Tue, 14 Jun 2016) $");
  script_tag(name:"creation_date", value:"2014-10-08 10:10:49 +0530 (Wed, 08 Oct 2014)");

  script_name("GNU Bash Environment Variable Handling Shell RCE Vulnerability (LSC) - 02");

  script_tag(name: "summary" , value:"This host is installed with GNU Bash Shell
  and is prone to remote command execution vulnerability.");

  script_tag(name: "vuldetect" , value:"Login to the target machine with ssh
  credentials and check its possible to execute the commands via GNU bash shell.");

  script_tag(name: "insight" , value:"GNU bash contains a flaw that is triggered
  when evaluating environment variables passed from another environment.
  After processing a function definition, bash continues to process trailing
  strings. Incomplete fix to CVE-2014-6271");

  script_tag(name: "impact" , value:"Successful exploitation will allow remote
  or local attackers to inject  shell commmands, allowing local privilege
  escalation or remote command execution depending on the application vector.

  Impact Level: System/Application");

  script_tag(name: "affected" , value:"GNU Bash through 4.3 bash43-025");

  script_tag(name: "solution" , value:"Apply the patch from the below link,
  https://ftp.gnu.org/gnu/bash/");

  script_xref(name : "URL" , value : "https://shellshocker.net/");
  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/252743");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2014/09/24/32");
  script_xref(name : "URL" , value : "https://community.qualys.com/blogs/securitylabs/2014/09/24/bash-remote-code-execution-vulnerability-cve-2014-6271");
  script_summary("Check for RCE vulnerability in GNU Bash");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/force/pty");
  exit(0);
}


include("ssh_func.inc");

if( get_kb_item( "ssh/force/pty" ) ) exit( 0 );

## Variable Initialization
sock = "";
cmd ="";
result = "";

## Confirm Linux, as SSH can be installed on Windows as well
result = get_kb_item("ssh/login/uname");
if("Linux" >!< result){
  exit(0);
}

## Checking OS
sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

if( ! get_kb_item( "shellshock/bash/installed" ) )
{
  cmd = "bash --version";
  result = ssh_cmd(socket:sock, cmd:cmd, nosh:TRUE);
  if( "GNU bash" >!< result ) exit( 0 );
  replace_kb_item( name:"shellshock/bash/installed", value:TRUE );
}

## Command to be executed
cmd = "cd /tmp; rm -f /tmp/echo; env X='() { (OpenVAS Test)=>\' bash -c 'echo id';cat echo ;rm -f /tmp/echo";
result = ssh_cmd(socket:sock, cmd:cmd, nosh:TRUE);
close(sock);

## check the result
if(result =~ "uid=[0-9]+.*gid=[0-9]+.*")
{
  security_message(0);
  exit(0);
}
